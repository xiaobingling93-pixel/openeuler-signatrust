/*
 *
 *  * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  * //
 *  * // signatrust is licensed under Mulan PSL v2.
 *  * // You can use this software according to the terms and conditions of the Mulan
 *  * // PSL v2.
 *  * // You may obtain a copy of Mulan PSL v2 at:
 *  * //         http://license.coscl.org.cn/MulanPSL2
 *  * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *  * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *  * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *  * // See the Mulan PSL v2 for more details.
 *
 */

use super::super::request_delete::dto as request_dto;
use super::super::user::dto as user_dto;
use super::super::x509_crl_content::dto as crl_content_dto;
use super::super::x509_revoked_key::dto as revoked_key_dto;
use super::dto as datakey_dto;
use crate::domain::datakey::entity::{
    DataKey, DatakeyPaginationQuery, KeyState, KeyType, PagedDatakey, PagedMeta, ParentKey,
    RevokedKey, Visibility, X509RevokeReason, X509CRL,
};
use crate::domain::datakey::repository::Repository;
use crate::infra::database::model::request_delete::dto::RequestType;
use crate::util::error::{Error, Result};
use crate::util::key::encode_u8_to_hex_string;
use async_trait::async_trait;
use chrono::Duration;
use chrono::Utc;
use sea_orm::sea_query::{Alias, IntoCondition, OnConflict};
use sea_orm::{
    sea_query, ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend,
    DatabaseConnection, DatabaseTransaction, EntityTrait, ExecResult, Iterable, JoinType, NotSet,
    PaginatorTrait, QueryFilter, QuerySelect, RelationBuilder, RelationTrait, Statement,
    TransactionTrait,
};
use sea_query::Expr;

const PUBLIC_KEY_PENDING_THRESHOLD: i32 = 3;
const PRIVATE_KEY_PENDING_THRESHOLD: i32 = 1;

#[derive(Clone)]
pub struct DataKeyRepository<'a> {
    db_connection: &'a DatabaseConnection,
}

impl<'a> DataKeyRepository<'a> {
    pub fn new(db_connection: &'a DatabaseConnection) -> Self {
        Self { db_connection }
    }

    async fn create_pending_operation(
        &self,
        pending_operation: request_dto::Model,
        tx: &DatabaseTransaction,
    ) -> Result<()> {
        let operation = request_dto::ActiveModel {
            user_id: Set(pending_operation.user_id),
            key_id: Set(pending_operation.key_id),
            request_type: Set(pending_operation.request_type),
            user_email: Set(pending_operation.user_email),
            create_at: Set(pending_operation.create_at),
            ..Default::default()
        };
        //TODO: https://github.com/SeaQL/sea-orm/issues/1790
        request_dto::Entity::insert(operation)
            .on_conflict(
                OnConflict::new()
                    .update_column(request_dto::Column::Id)
                    .to_owned(),
            )
            .exec(tx)
            .await?;
        Ok(())
    }

    async fn delete_pending_operation(
        &self,
        user_id: i32,
        id: i32,
        request_type: RequestType,
        tx: &DatabaseTransaction,
    ) -> Result<()> {
        let _ = request_dto::Entity::delete_many()
            .filter(
                Condition::all()
                    .add(request_dto::Column::UserId.eq(user_id))
                    .add(request_dto::Column::RequestType.eq(request_type.to_string()))
                    .add(request_dto::Column::KeyId.eq(id)),
            )
            .exec(tx)
            .await?;
        Ok(())
    }

    async fn create_revoke_record(
        &self,
        key_id: i32,
        ca_id: i32,
        reason: X509RevokeReason,
        tx: &DatabaseTransaction,
    ) -> Result<()> {
        let revoked = revoked_key_dto::ActiveModel {
            id: Default::default(),
            key_id: Set(key_id),
            ca_id: Set(ca_id),
            reason: Set(reason.to_string()),
            create_at: Set(Utc::now()),
            serial_number: NotSet,
        };
        //TODO: https://github.com/SeaQL/sea-orm/issues/1790
        revoked_key_dto::Entity::insert(revoked)
            .on_conflict(
                OnConflict::new()
                    .update_column(request_dto::Column::Id)
                    .to_owned(),
            )
            .exec(tx)
            .await?;
        Ok(())
    }

    async fn delete_revoke_record(
        &self,
        key_id: i32,
        ca_id: i32,
        tx: &DatabaseTransaction,
    ) -> Result<()> {
        let _ = revoked_key_dto::Entity::delete_many()
            .filter(
                Condition::all()
                    .add(revoked_key_dto::Column::KeyId.eq(key_id))
                    .add(revoked_key_dto::Column::CaId.eq(ca_id)),
            )
            .exec(tx)
            .await?;
        Ok(())
    }

    fn get_pending_operation_relation(
        &self,
        request_type: RequestType,
    ) -> RelationBuilder<request_dto::Entity, datakey_dto::Entity> {
        request_dto::Entity::belongs_to(datakey_dto::Entity)
            .from(request_dto::Column::KeyId)
            .to(datakey_dto::Column::Id)
            .on_condition(move |left, _right| {
                Expr::col((left, request_dto::Column::RequestType))
                    .eq(request_type.clone().to_string())
                    .into_condition()
            })
    }

    async fn _obtain_datakey_parent(&self, datakey: &mut DataKey) -> Result<()> {
        if let Some(parent) = datakey.parent_id {
            let result = self.get_by_id_or_name(Some(parent), None, true).await;
            match result {
                Ok(parent) => {
                    datakey.parent_key = Some(ParentKey {
                        name: parent.name,
                        private_key: parent.private_key.clone(),
                        public_key: parent.public_key.clone(),
                        certificate: parent.certificate.clone(),
                        attributes: parent.attributes,
                    })
                }
                _ => {
                    return Err(Error::DatabaseError(
                        "unable to find parent key".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<'a> Repository for DataKeyRepository<'a> {
    async fn create(&self, data_key: DataKey) -> Result<DataKey> {
        let dto = datakey_dto::ActiveModel::try_from(data_key)?;
        let insert_result = datakey_dto::Entity::insert(dto)
            .exec(self.db_connection)
            .await?;

        let mut datakey = self
            .get_by_id_or_name(Some(insert_result.last_insert_id), None, true)
            .await?;
        //fetch parent key if 'parent_id' exists.
        if let Err(err) = self._obtain_datakey_parent(&mut datakey).await {
            warn!("failed to create datakey {} {}", datakey.name, err);
            let _ = self.delete(insert_result.last_insert_id).await;
            return Err(err);
        }
        Ok(datakey)
    }

    async fn delete(&self, id: i32) -> Result<()> {
        datakey_dto::Entity::delete_by_id(id)
            .exec(self.db_connection)
            .await?;
        Ok(())
    }

    async fn get_all_keys(
        &self,
        user_id: i32,
        query: DatakeyPaginationQuery,
    ) -> Result<PagedDatakey> {
        let mut conditions =
            Condition::all().add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string()));
        if let Some(name) = query.name {
            conditions = conditions.add(datakey_dto::Column::Name.like(format!("%{}%", name)))
        }
        if let Some(desc) = query.description {
            conditions =
                conditions.add(datakey_dto::Column::Description.like(format!("%{}%", desc)))
        }
        if let Some(k_type) = query.key_type {
            conditions = conditions.add(datakey_dto::Column::KeyType.eq(k_type))
        }
        if let Some(visibility) = query.visibility {
            conditions = conditions.add(datakey_dto::Column::Visibility.eq(visibility.clone()));
            if visibility == Visibility::Private.to_string() {
                conditions = conditions.add(datakey_dto::Column::User.eq(user_id))
            }
        }
        let paginator = datakey_dto::Entity::find()
            .select_only()
            .columns(datakey_dto::Column::iter().filter(|col| {
                !matches!(
                    col,
                    datakey_dto::Column::UserEmail
                        | datakey_dto::Column::RequestDeleteUsers
                        | datakey_dto::Column::RequestRevokeUsers
                        | datakey_dto::Column::X509CrlUpdateAt
                )
            }))
            .exprs([
                Expr::cust("user_table.email as user_email"),
                Expr::cust("GROUP_CONCAT(request_delete_table.user_email) as request_delete_users"),
                Expr::cust("GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users"),
            ])
            .join_as_rev(
                JoinType::InnerJoin,
                user_dto::Relation::Datakey.def(),
                Alias::new("user_table"),
            )
            .join_as_rev(
                JoinType::LeftJoin,
                self.get_pending_operation_relation(RequestType::Delete)
                    .into(),
                Alias::new("request_delete_table"),
            )
            .join_as_rev(
                JoinType::LeftJoin,
                self.get_pending_operation_relation(RequestType::Revoke)
                    .into(),
                Alias::new("request_revoke_table"),
            )
            .group_by(datakey_dto::Column::Id)
            .filter(conditions)
            .paginate(self.db_connection, query.page_size);
        let total_numbers = paginator.num_items().await?;
        let mut results = vec![];
        for dto in paginator
            .fetch_page(query.page_number - 1)
            .await?
            .into_iter()
        {
            results.push(DataKey::try_from(dto)?);
        }
        Ok(PagedDatakey {
            data: results,
            meta: PagedMeta {
                total_count: total_numbers,
            },
        })
    }

    async fn get_keys_for_crl_update(&self, duration: Duration) -> Result<Vec<DataKey>> {
        let now = Utc::now();
        match datakey_dto::Entity::find()
            .select_only()
            .columns(datakey_dto::Column::iter().filter(|col| {
                !matches!(
                    col,
                    datakey_dto::Column::UserEmail
                        | datakey_dto::Column::RequestDeleteUsers
                        | datakey_dto::Column::RequestRevokeUsers
                        | datakey_dto::Column::X509CrlUpdateAt
                )
            }))
            .column_as(
                Expr::col((Alias::new("crl_table"), crl_content_dto::Column::UpdateAt)),
                "x509_crl_update_at",
            )
            .join_as_rev(
                JoinType::LeftJoin,
                crl_content_dto::Relation::Datakey.def(),
                Alias::new("crl_table"),
            )
            .filter(
                Condition::all()
                    .add(
                        Condition::any()
                            .add(datakey_dto::Column::KeyType.eq(KeyType::X509CA.to_string()))
                            .add(datakey_dto::Column::KeyType.eq(KeyType::X509ICA.to_string())),
                    )
                    .add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string())),
            )
            .all(self.db_connection)
            .await
        {
            Err(_) => Ok(vec![]),
            Ok(keys) => {
                let mut results = vec![];
                for dto in keys.into_iter() {
                    if dto.x509_crl_update_at.is_none() {
                        results.push(DataKey::try_from(dto)?);
                    } else {
                        let update_at = dto.x509_crl_update_at.unwrap();
                        if update_at + duration <= now {
                            results.push(DataKey::try_from(dto)?);
                        }
                    }
                }
                Ok(results)
            }
        }
    }

    async fn get_revoked_serial_number_by_parent_id(&self, id: i32) -> Result<Vec<RevokedKey>> {
        match revoked_key_dto::Entity::find()
            .select_only()
            .columns(
                revoked_key_dto::Column::iter()
                    .filter(|col| !matches!(col, revoked_key_dto::Column::SerialNumber)),
            )
            .column_as(
                Expr::col((
                    Alias::new("datakey_table"),
                    datakey_dto::Column::SerialNumber,
                )),
                "serial_number",
            )
            .join_as_rev(
                JoinType::InnerJoin,
                datakey_dto::Entity::belongs_to(revoked_key_dto::Entity)
                    .from(datakey_dto::Column::Id)
                    .to(revoked_key_dto::Column::KeyId)
                    .on_condition(move |left, right| {
                        Condition::all()
                            .add(
                                Expr::col((left, datakey_dto::Column::KeyState))
                                    .eq(KeyState::Revoked.to_string()),
                            )
                            .add(Expr::col((right, revoked_key_dto::Column::CaId)).eq(id))
                            .into_condition()
                    })
                    .into(),
                Alias::new("datakey_table"),
            )
            .all(self.db_connection)
            .await
        {
            Err(err) => {
                warn!("failed to query database {:?}", err);
                Err(Error::NotFoundError)
            }
            Ok(revoked_keys) => {
                let mut results = vec![];
                for dto in revoked_keys.into_iter() {
                    results.push(RevokedKey::try_from(dto)?);
                }
                Ok(results)
            }
        }
    }

    async fn get_by_id_or_name(
        &self,
        id: Option<i32>,
        name: Option<String>,
        raw_datakey: bool,
    ) -> Result<DataKey> {
        let mut conditions = Condition::all();
        if let Some(key_id) = id {
            conditions = conditions.add(datakey_dto::Column::Id.eq(key_id))
        } else if let Some(key_name) = name {
            conditions = conditions.add(datakey_dto::Column::Name.eq(key_name))
        } else {
            return Err(Error::ParameterError(
                "both datakey name and id are empty".to_string(),
            ));
        }
        conditions =
            conditions.add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string()));
        if !raw_datakey {
            match datakey_dto::Entity::find()
                .select_only()
                .columns(datakey_dto::Column::iter().filter(|col| {
                    !matches!(
                        col,
                        datakey_dto::Column::UserEmail
                            | datakey_dto::Column::RequestDeleteUsers
                            | datakey_dto::Column::RequestRevokeUsers
                            | datakey_dto::Column::X509CrlUpdateAt
                    )
                }))
                .exprs([
                    Expr::cust("user_table.email as user_email"),
                    Expr::cust(
                        "GROUP_CONCAT(request_delete_table.user_email) as request_delete_users",
                    ),
                    Expr::cust(
                        "GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users",
                    ),
                ])
                .join_as_rev(
                    JoinType::InnerJoin,
                    user_dto::Relation::Datakey.def(),
                    Alias::new("user_table"),
                )
                .join_as_rev(
                    JoinType::LeftJoin,
                    self.get_pending_operation_relation(RequestType::Delete)
                        .into(),
                    Alias::new("request_delete_table"),
                )
                .join_as_rev(
                    JoinType::LeftJoin,
                    self.get_pending_operation_relation(RequestType::Revoke)
                        .into(),
                    Alias::new("request_revoke_table"),
                )
                .group_by(datakey_dto::Column::Id)
                .filter(conditions)
                .one(self.db_connection)
                .await?
            {
                None => Err(Error::NotFoundError),
                Some(datakey) => Ok(DataKey::try_from(datakey)?),
            }
        } else {
            match datakey_dto::Entity::find()
                .select_only()
                .columns(datakey_dto::Column::iter().filter(|col| {
                    !matches!(
                        col,
                        datakey_dto::Column::UserEmail
                            | datakey_dto::Column::RequestDeleteUsers
                            | datakey_dto::Column::RequestRevokeUsers
                            | datakey_dto::Column::X509CrlUpdateAt
                    )
                }))
                .filter(conditions)
                .one(self.db_connection)
                .await?
            {
                None => Err(Error::NotFoundError),
                Some(datakey) => Ok(DataKey::try_from(datakey)?),
            }
        }
    }

    async fn get_by_parent_id(&self, parent_id: i32) -> Result<Vec<DataKey>> {
        match datakey_dto::Entity::find()
            .select_only()
            .columns(datakey_dto::Column::iter().filter(|col| {
                !matches!(
                    col,
                    datakey_dto::Column::UserEmail
                        | datakey_dto::Column::RequestDeleteUsers
                        | datakey_dto::Column::RequestRevokeUsers
                        | datakey_dto::Column::X509CrlUpdateAt
                )
            }))
            .exprs([
                Expr::cust("user_table.email as user_email"),
                Expr::cust("GROUP_CONCAT(request_delete_table.user_email) as request_delete_users"),
                Expr::cust("GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users"),
            ])
            .join_as_rev(
                JoinType::InnerJoin,
                user_dto::Relation::Datakey.def(),
                Alias::new("user_table"),
            )
            .join_as_rev(
                JoinType::LeftJoin,
                self.get_pending_operation_relation(RequestType::Delete)
                    .into(),
                Alias::new("request_delete_table"),
            )
            .join_as_rev(
                JoinType::LeftJoin,
                self.get_pending_operation_relation(RequestType::Revoke)
                    .into(),
                Alias::new("request_revoke_table"),
            )
            .group_by(datakey_dto::Column::Id)
            .filter(
                Condition::all()
                    .add(datakey_dto::Column::ParentId.eq(parent_id))
                    .add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string())),
            )
            .all(self.db_connection)
            .await
        {
            Err(err) => {
                warn!("failed to query database {:?}", err);
                Err(Error::NotFoundError)
            }
            Ok(data_keys) => {
                let mut results = vec![];
                for dto in data_keys.into_iter() {
                    results.push(DataKey::try_from(dto)?);
                }
                Ok(results)
            }
        }
    }

    async fn update_state(&self, id: i32, state: KeyState) -> Result<()> {
        //Note: if the key in deleted status, it cannot be updated to other states
        let _ = datakey_dto::Entity::update_many()
            .col_expr(
                datakey_dto::Column::KeyState,
                Expr::value(state.to_string()),
            )
            .filter(
                Condition::all()
                    .add(datakey_dto::Column::Id.eq(id))
                    .add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string())),
            )
            .exec(self.db_connection)
            .await?;
        Ok(())
    }

    async fn update_key_data(&self, data_key: DataKey) -> Result<()> {
        //Note: if the key in deleted status, it cannot be updated to other states
        let _ = datakey_dto::Entity::update_many()
            .col_expr(
                datakey_dto::Column::SerialNumber,
                Expr::value(data_key.serial_number),
            )
            .col_expr(
                datakey_dto::Column::Fingerprint,
                Expr::value(data_key.fingerprint),
            )
            .col_expr(
                datakey_dto::Column::PrivateKey,
                Expr::value(encode_u8_to_hex_string(&data_key.private_key)),
            )
            .col_expr(
                datakey_dto::Column::PublicKey,
                Expr::value(encode_u8_to_hex_string(&data_key.public_key)),
            )
            .col_expr(
                datakey_dto::Column::Certificate,
                Expr::value(encode_u8_to_hex_string(&data_key.certificate)),
            )
            .filter(
                Condition::all()
                    .add(datakey_dto::Column::Id.eq(data_key.id))
                    .add(datakey_dto::Column::KeyState.ne(KeyState::Deleted.to_string())),
            )
            .exec(self.db_connection)
            .await?;
        Ok(())
    }

    async fn get_enabled_key_by_type_and_name_with_parent_key(
        &self,
        key_type: Option<String>,
        name: String,
    ) -> Result<DataKey> {
        let mut cond = Condition::all();
        cond = cond.add(datakey_dto::Column::Name.eq(name));
        if let Some(t) = key_type {
            cond = cond.add(datakey_dto::Column::KeyType.eq(t));
        }
        cond = cond.add(datakey_dto::Column::KeyState.eq(KeyState::Enabled.to_string()));

        match datakey_dto::Entity::find()
            .select_only()
            .columns(datakey_dto::Column::iter().filter(|col| {
                !matches!(
                    col,
                    datakey_dto::Column::UserEmail
                        | datakey_dto::Column::RequestDeleteUsers
                        | datakey_dto::Column::RequestRevokeUsers
                        | datakey_dto::Column::X509CrlUpdateAt
                )
            }))
            .filter(cond)
            .one(self.db_connection)
            .await?
        {
            None => Err(Error::NotFoundError),
            Some(datakey) => {
                let mut result = DataKey::try_from(datakey)?;
                self._obtain_datakey_parent(&mut result).await?;
                Ok(result)
            }
        }
    }

    async fn request_delete_key(
        &self,
        user_id: i32,
        user_email: String,
        id: i32,
        public_key: bool,
    ) -> Result<()> {
        let txn = self.db_connection.begin().await?;
        let threshold = if public_key {
            PUBLIC_KEY_PENDING_THRESHOLD
        } else {
            PRIVATE_KEY_PENDING_THRESHOLD
        };
        //1. update key state to pending delete if needed.
        let _ = datakey_dto::Entity::update_many()
            .col_expr(
                datakey_dto::Column::KeyState,
                Expr::value(KeyState::PendingDelete.to_string()),
            )
            .filter(datakey_dto::Column::Id.eq(id))
            .exec(&txn)
            .await?;
        //2. add request delete record
        let pending_delete = request_dto::Model::new_for_delete(id, user_id, user_email);
        self.create_pending_operation(pending_delete, &txn).await?;
        //3. delete datakey if pending delete count >= threshold
        let _: ExecResult = txn
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?",
                [
                    KeyState::Deleted.to_string().into(),
                    id.into(),
                    id.into(),
                    threshold.into(),
                ],
            ))
            .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn request_revoke_key(
        &self,
        user_id: i32,
        user_email: String,
        id: i32,
        parent_id: i32,
        reason: X509RevokeReason,
        public_key: bool,
    ) -> Result<()> {
        let txn = self.db_connection.begin().await?;
        let threshold = if public_key {
            PUBLIC_KEY_PENDING_THRESHOLD
        } else {
            PRIVATE_KEY_PENDING_THRESHOLD
        };
        //1. update key state to pending delete if needed.
        let _ = datakey_dto::Entity::update_many()
            .col_expr(
                datakey_dto::Column::KeyState,
                Expr::value(KeyState::PendingDelete.to_string()),
            )
            .filter(datakey_dto::Column::Id.eq(id))
            .exec(&txn)
            .await?;
        //2. add request revoke pending record
        let pending_revoke = request_dto::Model::new_for_revoke(id, user_id, user_email);
        self.create_pending_operation(pending_revoke, &txn).await?;
        //3. add revoked record
        self.create_revoke_record(id, parent_id, reason, &txn)
            .await?;
        //4. mark datakey revoked if pending revoke count >= threshold
        let _: ExecResult = txn
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?",
                [
                    KeyState::Revoked.to_string().into(),
                    id.into(),
                    id.into(),
                    threshold.into(),
                ],
            ))
            .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn cancel_delete_key(&self, user_id: i32, id: i32) -> Result<()> {
        let txn = self.db_connection.begin().await?;
        //1. delete pending delete record
        self.delete_pending_operation(user_id, id, RequestType::Delete, &txn)
            .await?;
        //2. update status if there is not any pending delete record.
        let _: ExecResult = txn
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) = ?",
                [
                    KeyState::Disabled.to_string().into(),
                    id.into(),
                    id.into(),
                    0i32.into(),
                ],
            ))
            .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn cancel_revoke_key(&self, user_id: i32, id: i32, parent_id: i32) -> Result<()> {
        let txn = self.db_connection.begin().await?;
        //1. delete pending delete record
        self.delete_pending_operation(user_id, id, RequestType::Revoke, &txn)
            .await?;
        //2. delete revoked record
        self.delete_revoke_record(id, parent_id, &txn).await?;
        //3. update status if there is not any pending delete record.
        let _: ExecResult = txn
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE data_key SET key_state = ? \
                WHERE id = ? AND ( \
                SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) = ?",
                [
                    KeyState::Disabled.to_string().into(),
                    id.into(),
                    id.into(),
                    0i32.into(),
                ],
            ))
            .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn get_x509_crl_by_ca_id(&self, id: i32) -> Result<X509CRL> {
        match crl_content_dto::Entity::find()
            .filter(crl_content_dto::Column::CaId.eq(id))
            .one(self.db_connection)
            .await?
        {
            None => Err(Error::NotFoundError),
            Some(content) => Ok(X509CRL::try_from(content)?),
        }
    }

    async fn upsert_x509_crl(&self, crl: X509CRL) -> Result<()> {
        let ca_id = crl.ca_id;
        let crl_model = crl_content_dto::ActiveModel {
            id: Set(crl.id),
            ca_id: Set(crl.ca_id),
            data: Set(encode_u8_to_hex_string(&crl.data)),
            create_at: Set(crl.create_at),
            update_at: Set(crl.update_at),
        };
        match self.get_x509_crl_by_ca_id(ca_id).await {
            Ok(_) => {
                //update crl content with new version
                crl_content_dto::Entity::update(crl_model.clone())
                    .filter(crl_content_dto::Column::CaId.eq(ca_id))
                    .exec(self.db_connection)
                    .await?;
            }
            Err(_) => {
                crl_content_dto::Entity::insert(crl_model)
                    .exec(self.db_connection)
                    .await?;
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::request_delete::dto as request_dto;
    use super::super::super::x509_revoked_key::dto as revoked_key_dto;
    use crate::domain::datakey::entity::{
        DataKey, KeyState, KeyType, ParentKey, RevokedKey, Visibility,
    };
    use crate::domain::datakey::repository::Repository;
    use crate::infra::database::model::datakey::dto;
    use crate::infra::database::model::datakey::repository::DataKeyRepository;
    use crate::infra::database::model::request_delete::dto::RequestType;
    use crate::util::error::Result;
    use chrono::Duration;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction, TransactionTrait};
    use std::collections::HashMap;

    // unmark me when "num_items" issue fixed.
    // #[tokio::test]
    // async fn test_datakey_repository_get_all_sql_statement() -> Result<()> {
    //     let now = chrono::Utc::now();
    //     let db = MockDatabase::new(DatabaseBackend::MySql)
    //         .append_query_results([
    //             //get public
    //             vec![dto::Model {
    //                 id: 1,
    //                 name: "Test Key".to_string(),
    //                 description: "".to_string(),
    //                 visibility: Visibility::Public.to_string(),
    //                 user: 0,
    //                 attributes: "{}".to_string(),
    //                 key_type: "pgp".to_string(),
    //                 parent_id: None,
    //                 fingerprint: "".to_string(),
    //                 serial_number: None,
    //                 private_key: "0708090A".to_string(),
    //                 public_key: "040506".to_string(),
    //                 certificate: "010203".to_string(),
    //                 create_at: now.clone(),
    //                 expire_at: now.clone(),
    //                 key_state: "disabled".to_string(),
    //                 user_email: None,
    //                 request_delete_users: None,
    //                 request_revoke_users: None,
    //                 x509_crl_update_at: None,
    //             }],
    //             //get private
    //             vec![dto::Model {
    //                 id: 1,
    //                 name: "Test Key".to_string(),
    //                 description: "".to_string(),
    //                 visibility: Visibility::Public.to_string(),
    //                 user: 0,
    //                 attributes: "{}".to_string(),
    //                 key_type: "pgp".to_string(),
    //                 parent_id: None,
    //                 fingerprint: "".to_string(),
    //                 serial_number: None,
    //                 private_key: "0708090A".to_string(),
    //                 public_key: "040506".to_string(),
    //                 certificate: "010203".to_string(),
    //                 create_at: now.clone(),
    //                 expire_at: now.clone(),
    //                 key_state: "disabled".to_string(),
    //                 user_email: None,
    //                 request_delete_users: None,
    //                 request_revoke_users: None,
    //                 x509_crl_update_at: None,
    //             }],
    //             //get private with type
    //             vec![dto::Model {
    //                 id: 1,
    //                 name: "Test Key".to_string(),
    //                 description: "".to_string(),
    //                 visibility: Visibility::Public.to_string(),
    //                 user: 0,
    //                 attributes: "{}".to_string(),
    //                 key_type: "pgp".to_string(),
    //                 parent_id: None,
    //                 fingerprint: "".to_string(),
    //                 serial_number: None,
    //                 private_key: "0708090A".to_string(),
    //                 public_key: "040506".to_string(),
    //                 certificate: "010203".to_string(),
    //                 create_at: now.clone(),
    //                 expire_at: now.clone(),
    //                 key_state: "disabled".to_string(),
    //                 user_email: None,
    //                 request_delete_users: None,
    //                 request_revoke_users: None,
    //                 x509_crl_update_at: None,
    //             }],
    //         ]).into_connection();
    //
    //     let datakey_repository = DataKeyRepository::new(&db);
    //     let datakey = DataKey{
    //         id: 1,
    //         name: "Test Key".to_string(),
    //         description: "".to_string(),
    //         visibility: Visibility::Public,
    //         user: 0,
    //         attributes: HashMap::new(),
    //         key_type: KeyType::OpenPGP,
    //         parent_id: None,
    //         fingerprint: "".to_string(),
    //         serial_number: None,
    //         private_key: vec![7,8,9,10],
    //         public_key: vec![4,5,6],
    //         certificate: vec![1,2,3],
    //         create_at: now.clone(),
    //         expire_at: now.clone(),
    //         key_state: KeyState::Disabled,
    //         user_email: None,
    //         request_delete_users: None,
    //         request_revoke_users: None,
    //         parent_key: None,
    //     };
    //     assert_eq!(
    //         datakey_repository.get_all_keys(None, Visibility::Public, 1, 10, 1).await?.data, vec![datakey.clone()]
    //     );
    //     assert_eq!(
    //         datakey_repository.get_all_keys(None, Visibility::Private, 1, 10, 1).await?.data, vec![datakey.clone()]
    //     );
    //     assert_eq!(
    //         datakey_repository.get_all_keys(Some(KeyType::OpenPGP), Visibility::Private, 1,10, 1).await?.data, vec![datakey]
    //     );
    //     assert_eq!(
    //         db.into_transaction_log(),
    //         [
    //             Transaction::from_sql_and_values(
    //                 DatabaseBackend::MySql,
    //                 r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`key_state` <> ? AND `data_key`.`visibility` = ? GROUP BY `data_key`.`id`"#,
    //                 ["delete".into(), "revoke".into(), "deleted".into(), "public".into()]
    //             ),
    //             Transaction::from_sql_and_values(
    //                 DatabaseBackend::MySql,
    //                 r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`key_state` <> ? AND `data_key`.`visibility` = ? AND `data_key`.`user` = ? GROUP BY `data_key`.`id`"#,
    //                 ["delete".into(), "revoke".into(), "deleted".into(), "private".into(), 1i32.into()]
    //             ),
    //             Transaction::from_sql_and_values(
    //                 DatabaseBackend::MySql,
    //                 r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`key_state` <> ? AND `data_key`.`visibility` = ? AND `data_key`.`key_type` = ? AND `data_key`.`user` = ? GROUP BY `data_key`.`id`"#,
    //                 ["delete".into(), "revoke".into(), "deleted".into(), "private".into(), "pgp".into(), 1i32.into()]
    //             ),
    //         ]
    //     );
    //
    //     Ok(())
    // }
    #[tokio::test]
    async fn test_datakey_repository_get_by_id_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                name: "Test Key".to_string(),
                description: "".to_string(),
                visibility: Visibility::Public.to_string(),
                user: 0,
                attributes: "{}".to_string(),
                key_type: "pgp".to_string(),
                parent_id: None,
                fingerprint: "".to_string(),
                serial_number: None,
                private_key: "0708090A".to_string(),
                public_key: "040506".to_string(),
                certificate: "010203".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
                key_state: "disabled".to_string(),
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                x509_crl_update_at: None,
            }]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let user = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert_eq!(
            datakey_repository
                .get_by_id_or_name(Some(1), None, false)
                .await?,
            user
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ? GROUP BY `data_key`.`id` LIMIT ?"#,
                [
                    "delete".into(),
                    "revoke".into(),
                    1i32.into(),
                    "deleted".into(),
                    1u64.into()
                ]
            ),]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_update_key_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_exec_results([
                MockExecResult {
                    last_insert_id: 1,
                    rows_affected: 1,
                },
                MockExecResult {
                    last_insert_id: 1,
                    rows_affected: 1,
                },
            ])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let datakey = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "456".to_string(),
            serial_number: Some("123".to_string()),
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert_eq!(
            datakey_repository
                .update_state(1, KeyState::Enabled)
                .await?,
            ()
        );
        assert_eq!(datakey_repository.update_key_data(datakey).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"UPDATE `data_key` SET `key_state` = ? WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ?"#,
                    [
                        KeyState::Enabled.to_string().into(),
                        1i32.into(),
                        "deleted".into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"UPDATE `data_key` SET `serial_number` = ?, `fingerprint` = ?, `private_key` = ?, `public_key` = ?, `certificate` = ? WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ?"#,
                    [
                        "123".into(),
                        "456".into(),
                        "0708090A".into(),
                        "040506".into(),
                        "010203".into(),
                        1i32.into(),
                        "deleted".into()
                    ]
                )
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_get_keys_for_crl_update_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                name: "Test Key".to_string(),
                description: "".to_string(),
                visibility: Visibility::Public.to_string(),
                user: 0,
                attributes: "{}".to_string(),
                key_type: "pgp".to_string(),
                parent_id: None,
                fingerprint: "456".to_string(),
                serial_number: Some("123".to_string()),
                private_key: "0708090A".to_string(),
                public_key: "040506".to_string(),
                certificate: "010203".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
                key_state: "disabled".to_string(),
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                x509_crl_update_at: None,
            }]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let datakey = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "456".to_string(),
            serial_number: Some("123".to_string()),
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let duration = Duration::days(1);
        assert_eq!(
            datakey_repository.get_keys_for_crl_update(duration).await?,
            vec![datakey]
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, `crl_table`.`update_at` AS `x509_crl_update_at` FROM `data_key` LEFT JOIN `x509_crl_content` AS `crl_table` ON `crl_table`.`ca_id` = `data_key`.`id` WHERE (`data_key`.`key_type` = ? OR `data_key`.`key_type` = ?) AND `data_key`.`key_state` <> ?"#,
                [
                    KeyType::X509CA.to_string().into(),
                    KeyType::X509ICA.to_string().into(),
                    "deleted".into()
                ]
            )]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_get_revoked_serial_number_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![revoked_key_dto::Model {
                id: 1,
                key_id: 1,
                ca_id: 1,
                serial_number: Some("123".to_string()),
                create_at: now.clone(),
                reason: "unspecified".to_string(),
            }]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let revoked_key = revoked_key_dto::Model {
            id: 1,
            key_id: 1,
            ca_id: 1,
            serial_number: Some("123".to_string()),
            create_at: now.clone(),
            reason: "unspecified".to_string(),
        };
        assert_eq!(
            datakey_repository
                .get_revoked_serial_number_by_parent_id(1)
                .await?,
            vec![RevokedKey::try_from(revoked_key)?]
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `x509_keys_revoked`.`id`, `x509_keys_revoked`.`key_id`, `x509_keys_revoked`.`ca_id`, `x509_keys_revoked`.`reason`, `x509_keys_revoked`.`create_at`, `datakey_table`.`serial_number` AS `serial_number` FROM `x509_keys_revoked` INNER JOIN `data_key` AS `datakey_table` ON `datakey_table`.`id` = `x509_keys_revoked`.`key_id` AND (`datakey_table`.`key_state` = ? AND `x509_keys_revoked`.`ca_id` = ?)"#,
                [KeyState::Revoked.to_string().into(), 1i32.into()]
            )]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_get_raw_key_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                name: "Test Key".to_string(),
                description: "".to_string(),
                visibility: Visibility::Public.to_string(),
                user: 0,
                attributes: "{}".to_string(),
                key_type: "pgp".to_string(),
                parent_id: None,
                fingerprint: "".to_string(),
                serial_number: None,
                private_key: "0708090A".to_string(),
                public_key: "040506".to_string(),
                certificate: "010203".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
                key_state: "disabled".to_string(),
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                x509_crl_update_at: None,
            }]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let user = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert_eq!(
            datakey_repository
                .get_by_id_or_name(None, Some("Test Key".to_string()), true)
                .await?,
            user
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state` FROM `data_key` WHERE `data_key`.`name` = ? AND `data_key`.`key_state` <> ? LIMIT ?"#,
                ["Test Key".into(), "deleted".into(), 1u64.into()]
            ),]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_get_by_name_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                name: "Test Key".to_string(),
                description: "".to_string(),
                visibility: Visibility::Public.to_string(),
                user: 0,
                attributes: "{}".to_string(),
                key_type: "pgp".to_string(),
                parent_id: None,
                fingerprint: "".to_string(),
                serial_number: None,
                private_key: "0708090A".to_string(),
                public_key: "040506".to_string(),
                certificate: "010203".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
                key_state: "disabled".to_string(),
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                x509_crl_update_at: None,
            }]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let user = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert_eq!(
            datakey_repository
                .get_by_id_or_name(None, Some("Test Key".to_string()), false)
                .await?,
            user
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`name` = ? AND `data_key`.`key_state` <> ? GROUP BY `data_key`.`id` LIMIT ?"#,
                [
                    "delete".into(),
                    "revoke".into(),
                    "Test Key".into(),
                    "deleted".into(),
                    1u64.into()
                ]
            ),]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_delete_datakey_sql_statement() -> Result<()> {
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            }])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        assert_eq!(datakey_repository.delete(1).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"DELETE FROM `data_key` WHERE `data_key`.`id` = ?"#,
                [1i32.into()]
            ),]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_get_enabled_key_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    name: "Test Key".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: Some(2),
                    fingerprint: "".to_string(),
                    serial_number: None,
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                }],
                vec![dto::Model {
                    id: 2,
                    name: "Parent Key".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: None,
                    fingerprint: "".to_string(),
                    serial_number: None,
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                }],
            ])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let user = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: Some(2),
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: Some(ParentKey {
                name: "Parent Key".to_string(),
                attributes: HashMap::new(),
                private_key: vec![7, 8, 9, 10],
                public_key: vec![4, 5, 6],
                certificate: vec![1, 2, 3],
            }),
        };
        assert_eq!(
            datakey_repository
                .get_enabled_key_by_type_and_name_with_parent_key(
                    Some("openpgp".to_string()),
                    "fake_name".to_string()
                )
                .await?,
            user
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state` FROM `data_key` WHERE `data_key`.`name` = ? AND `data_key`.`key_type` = ? AND `data_key`.`key_state` = ? LIMIT ?"#,
                    [
                        "fake_name".into(),
                        "openpgp".into(),
                        "enabled".into(),
                        1u64.into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state` FROM `data_key` WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ? LIMIT ?"#,
                    [2i32.into(), "deleted".into(), 1u64.into()]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_create_datakey_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    name: "Test Key".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: Some(2),
                    fingerprint: "".to_string(),
                    serial_number: Some("123".to_string()),
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                }],
                vec![dto::Model {
                    id: 2,
                    name: "Test Parent Key".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: None,
                    fingerprint: "".to_string(),
                    serial_number: Some("123".to_string()),
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let datakey = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: Some(2),
            fingerprint: "".to_string(),
            serial_number: Some("123".to_string()),
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: Some(ParentKey {
                name: "Test Parent Key".to_string(),
                private_key: vec![7, 8, 9, 10],
                public_key: vec![4, 5, 6],
                certificate: vec![1, 2, 3],
                attributes: HashMap::new(),
            }),
        };
        assert_eq!(datakey_repository.create(datakey.clone()).await?, datakey);
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"INSERT INTO `data_key` (`id`, `name`, `description`, `visibility`, `user`, `attributes`, `key_type`, `parent_id`, `fingerprint`, `serial_number`, `private_key`, `public_key`, `certificate`, `create_at`, `expire_at`, `key_state`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                    [
                        1i32.into(),
                        "Test Key".into(),
                        "".into(),
                        "public".into(),
                        0i32.into(),
                        "{}".into(),
                        "pgp".into(),
                        2i32.into(),
                        "".into(),
                        "123".into(),
                        "0708090A".into(),
                        "040506".into(),
                        "010203".into(),
                        now.clone().into(),
                        now.clone().into(),
                        "disabled".into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state` FROM `data_key` WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ? LIMIT ?"#,
                    [1i32.into(), "deleted".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state` FROM `data_key` WHERE `data_key`.`id` = ? AND `data_key`.`key_state` <> ? LIMIT ?"#,
                    [2i32.into(), "deleted".into(), 1u64.into()]
                )
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_get_keys_by_parent_id_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![
                dto::Model {
                    id: 1,
                    name: "Test Key".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: None,
                    fingerprint: "".to_string(),
                    serial_number: None,
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                },
                dto::Model {
                    id: 2,
                    name: "Test Key2".to_string(),
                    description: "".to_string(),
                    visibility: Visibility::Public.to_string(),
                    user: 0,
                    attributes: "{}".to_string(),
                    key_type: "pgp".to_string(),
                    parent_id: None,
                    fingerprint: "".to_string(),
                    serial_number: None,
                    private_key: "0708090A".to_string(),
                    public_key: "040506".to_string(),
                    certificate: "010203".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                    key_state: "disabled".to_string(),
                    user_email: None,
                    request_delete_users: None,
                    request_revoke_users: None,
                    x509_crl_update_at: None,
                },
            ]])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let datakey1 = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let datakey2 = DataKey {
            id: 2,
            name: "Test Key2".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: now.clone(),
            expire_at: now.clone(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert_eq!(
            datakey_repository.get_by_parent_id(1).await?,
            vec![datakey1, datakey2]
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::MySql,
                r#"SELECT `data_key`.`id`, `data_key`.`name`, `data_key`.`description`, `data_key`.`visibility`, `data_key`.`user`, `data_key`.`attributes`, `data_key`.`key_type`, `data_key`.`parent_id`, `data_key`.`fingerprint`, `data_key`.`serial_number`, `data_key`.`private_key`, `data_key`.`public_key`, `data_key`.`certificate`, `data_key`.`create_at`, `data_key`.`expire_at`, `data_key`.`key_state`, user_table.email as user_email, GROUP_CONCAT(request_delete_table.user_email) as request_delete_users, GROUP_CONCAT(request_revoke_table.user_email) as request_revoke_users FROM `data_key` INNER JOIN `user` AS `user_table` ON `user_table`.`id` = `data_key`.`user` LEFT JOIN `pending_operation` AS `request_delete_table` ON `request_delete_table`.`key_id` = `data_key`.`id` AND `request_delete_table`.`request_type` = ? LEFT JOIN `pending_operation` AS `request_revoke_table` ON `request_revoke_table`.`key_id` = `data_key`.`id` AND `request_revoke_table`.`request_type` = ? WHERE `data_key`.`parent_id` = ? AND `data_key`.`key_state` <> ? GROUP BY `data_key`.`id`"#,
                [
                    "delete".into(),
                    "revoke".into(),
                    1i32.into(),
                    "deleted".into()
                ]
            ),]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_repository_create_delete_pending_operation_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let datakey_repository = DataKeyRepository::new(&db);
        let mut tx = db.begin().await?;
        assert_eq!(
            datakey_repository
                .create_pending_operation(
                    request_dto::Model {
                        id: 0,
                        user_id: 1,
                        key_id: 1,
                        request_type: RequestType::Delete.to_string(),
                        user_email: "fake_email".to_string(),
                        create_at: now,
                    },
                    &mut tx
                )
                .await?,
            ()
        );
        tx.commit().await?;
        //TODO 1.Now mock database begin statement is configured with postgres backend, enabled this when fixed in upstream
        // assert_eq!(
        //     db.into_transaction_log(),
        //     [
        //         Transaction::many(
        //             [
        //                 Statement::from_sql_and_values(DatabaseBackend::Postgres,
        //                                                r#"BEGIN"#,
        //                                                []),
        //                 Statement::from_sql_and_values(
        //                     DatabaseBackend::MySql,
        //                     r#"INSERT INTO `pending_operation` (`user_id`, `key_id`, `request_type`, `user_email`, `create_at`) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `id` = VALUES(`id`)"#,
        //                     [1i32.into(), 1i32.into(), "delete".into(), "fake_email".into()]
        //                 ),
        //                 Statement::from_sql_and_values(
        //                     DatabaseBackend::MySql,
        //                     r#"COMMIT"#,
        //                     []
        //                 ),
        //             ],
        //         ),
        //     ]
        // );
        Ok(())
    }
}
