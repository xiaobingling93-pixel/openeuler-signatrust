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

use crate::domain::datakey::entity::{
    DataKey, DatakeyPaginationQuery, KeyAction, KeyState, KeyType, PagedDatakey, Visibility,
    X509RevokeReason, X509CRL,
};
use crate::domain::datakey::repository::Repository as DatakeyRepository;
use crate::domain::sign_service::SignBackend;
use crate::util::error::{Error, Result};
use crate::util::options;
use async_trait::async_trait;
use tokio::time::{self};

use crate::domain::datakey::entity::KeyType::{OpenPGP, X509CA, X509EE, X509ICA};
use crate::presentation::handler::control::model::user::dto::UserIdentity;
use crate::util::cache::TimedFixedSizeCache;
use chrono::{Duration, Utc};
#[cfg(feature = "cert_expirtion_check")]
mod kafka_imports {
    pub(super) use chrono::DateTime;
    pub(super) use rdkafka::config::ClientConfig;
    pub(super) use rdkafka::producer::{FutureProducer, FutureRecord};
}
#[cfg(feature = "cert_expirtion_check")]
use kafka_imports::*;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
struct Email {
    name: String,
}

#[derive(Serialize)]
struct ExpiredCert {
    name: String,
    expire_at: String,
}

#[derive(Serialize)]
struct CertReport {
    domain: String,
    expired_certs: Vec<ExpiredCert>,
}

fn generate_cert_expire_json(keys: Vec<DataKey>, domain: String) -> Result<String> {
    let expired_certs = keys
        .into_iter()
        .map(|k| ExpiredCert {
            name: k.name,
            expire_at: k.expire_at.to_string(),
        })
        .collect();

    let report = CertReport {
        domain: domain.to_string(),
        expired_certs,
    };

    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}

#[async_trait]
pub trait KeyService: Send + Sync {
    async fn create(&self, user: UserIdentity, data: &mut DataKey) -> Result<DataKey>;
    async fn import(&self, data: &mut DataKey) -> Result<DataKey>;
    async fn get_raw_key_by_name(&self, name: &str) -> Result<DataKey>;

    async fn get_all(&self, user_id: i32, query: DatakeyPaginationQuery) -> Result<PagedDatakey>;
    async fn get_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey>;
    //get keys content
    async fn export_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey>;
    async fn get_inner_one(&self, id_name: String) -> Result<DataKey>;
    async fn export_cert_crl(
        &self,
        user: Option<UserIdentity>,
        id_or_name: String,
    ) -> Result<X509CRL>;
    //keys related operation
    async fn request_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn cancel_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn request_revoke(
        &self,
        user: UserIdentity,
        id_or_name: String,
        reason: X509RevokeReason,
    ) -> Result<()>;
    async fn cancel_revoke(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn enable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()>;
    async fn disable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()>;
    //used for data server
    async fn sign(
        &self,
        key_type: String,
        key_name: String,
        options: &HashMap<String, String>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;
    async fn get_by_type_and_name(
        &self,
        key_type: Option<String>,
        key_name: String,
    ) -> Result<DataKey>;
    async fn get_timestamp_key_by_type_and_name(
        &self,
        key_type: Option<String>,
        key_name: String,
    ) -> Result<DataKey>;
    //method below used for maintenance
    fn start_key_rotate_loop(&self, cancel_token: CancellationToken) -> Result<()>;

    //method below used for x509 crl
    fn start_key_plugin_maintenance(
        &self,
        cancel_token: CancellationToken,
        refresh_days: i32,
    ) -> Result<()>;

    fn start_cert_validity_period_check(
        &self,
        domain: String,
        adress: String,
        topic: String,
    ) -> Result<()>;
}

pub struct DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static,
{
    repository: R,
    sign_service: Arc<RwLock<Box<S>>>,
    container: TimedFixedSizeCache,
    timestamp_container: TimedFixedSizeCache,
}

impl<R, S> DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static,
{
    pub fn new(repository: R, sign_service: Box<S>) -> Self {
        Self {
            repository,
            sign_service: Arc::new(RwLock::new(sign_service)),
            container: TimedFixedSizeCache::new(Some(100), None, None, None),
            timestamp_container: TimedFixedSizeCache::new(Some(100), None, None, None),
        }
    }

    async fn get_and_check_permission(
        &self,
        user: Option<UserIdentity>,
        id_or_name: String,
        action: KeyAction,
        raw_key: bool,
    ) -> Result<DataKey> {
        let id = id_or_name.parse::<i32>();
        let data_key: DataKey = match id {
            Ok(id) => {
                self.repository
                    .get_by_id_or_name(Some(id), None, raw_key)
                    .await?
            }
            Err(_) => {
                self.repository
                    .get_by_id_or_name(None, Some(id_or_name), raw_key)
                    .await?
            }
        };
        //check permission for private keys
        if data_key.visibility == Visibility::Private
            && (user.is_none() || data_key.user != user.unwrap().id)
        {
            return Err(Error::UnprivilegedError);
        }
        self.validate_type_and_state(&data_key, action)?;
        Ok(data_key)
    }

    fn validate_type_and_state(&self, key: &DataKey, key_action: KeyAction) -> Result<()> {
        let valid_action_by_key_type = HashMap::from([
            (
                OpenPGP,
                vec![
                    KeyAction::Delete,
                    KeyAction::CancelDelete,
                    KeyAction::Disable,
                    KeyAction::Enable,
                    KeyAction::Sign,
                    KeyAction::Read,
                ],
            ),
            (
                X509CA,
                vec![
                    KeyAction::Delete,
                    KeyAction::CancelDelete,
                    KeyAction::Disable,
                    KeyAction::Enable,
                    KeyAction::IssueCert,
                    KeyAction::Read,
                ],
            ),
            (
                X509ICA,
                vec![
                    KeyAction::Delete,
                    KeyAction::CancelDelete,
                    KeyAction::Revoke,
                    KeyAction::CancelRevoke,
                    KeyAction::Disable,
                    KeyAction::Enable,
                    KeyAction::Read,
                    KeyAction::IssueCert,
                ],
            ),
            (
                X509EE,
                vec![
                    KeyAction::Delete,
                    KeyAction::CancelDelete,
                    KeyAction::Revoke,
                    KeyAction::CancelRevoke,
                    KeyAction::Disable,
                    KeyAction::Enable,
                    KeyAction::Read,
                    KeyAction::Sign,
                ],
            ),
        ]);

        let valid_state_by_key_action = HashMap::from([
            (
                KeyAction::Delete,
                vec![
                    KeyState::Disabled,
                    KeyState::Revoked,
                    KeyState::PendingDelete,
                ],
            ),
            (KeyAction::CancelDelete, vec![KeyState::PendingDelete]),
            (
                KeyAction::Revoke,
                vec![KeyState::Disabled, KeyState::PendingRevoke],
            ),
            (KeyAction::CancelRevoke, vec![KeyState::PendingRevoke]),
            (KeyAction::Enable, vec![KeyState::Disabled]),
            (KeyAction::Disable, vec![KeyState::Enabled]),
            (
                KeyAction::Sign,
                vec![
                    KeyState::Enabled,
                    KeyState::PendingDelete,
                    KeyState::PendingRevoke,
                ],
            ),
            (
                KeyAction::IssueCert,
                vec![
                    KeyState::Enabled,
                    KeyState::PendingDelete,
                    KeyState::PendingRevoke,
                ],
            ),
            (
                KeyAction::Read,
                vec![
                    KeyState::Enabled,
                    KeyState::PendingDelete,
                    KeyState::PendingRevoke,
                    KeyState::Disabled,
                ],
            ),
        ]);
        match valid_action_by_key_type.get(&key.key_type) {
            None => {
                return Err(Error::ConfigError(
                    "key type is missing, please check the key type".to_string(),
                ));
            }
            Some(actions) => {
                if !actions.contains(&key_action) {
                    return Err(Error::ActionsNotAllowedError(format!(
                        "action '{}' is not permitted for key type '{}'",
                        key_action, key.key_type
                    )));
                }
            }
        }
        match valid_state_by_key_action.get(&key_action) {
            None => {
                return Err(Error::ConfigError(
                    "key action is missing, please check the key action".to_string(),
                ))
            }
            Some(states) => {
                if !states.contains(&key.key_state) {
                    return Err(Error::ActionsNotAllowedError(format!(
                        "action '{}' is not permitted for state '{}'",
                        key_action, key.key_state
                    )));
                }
            }
        }
        if (key_action == KeyAction::Revoke || key_action == KeyAction::CancelRevoke)
            && key.parent_id.is_none()
        {
            return Err(Error::ActionsNotAllowedError(format!(
                "action '{}' is not permitted for key without parent",
                key_action
            )));
        }
        Ok(())
    }
    async fn check_key_hierarchy(
        &self,
        user: UserIdentity,
        data: &DataKey,
        parent_id: i32,
    ) -> Result<()> {
        let parent_key = self
            .repository
            .get_by_id_or_name(Some(parent_id), None, true)
            .await?;
        //check permission for private keys
        if parent_key.visibility == Visibility::Private && parent_key.user != user.id {
            return Err(Error::UnprivilegedError);
        }
        if parent_key.visibility != data.visibility {
            return Err(Error::ActionsNotAllowedError(format!(
                "parent key '{}' visibility not equal to current datakey",
                parent_key.name
            )));
        }
        if parent_key.key_state != KeyState::Enabled {
            return Err(Error::ActionsNotAllowedError(format!(
                "parent key '{}' not in enable state",
                parent_key.name
            )));
        }
        if parent_key.expire_at < data.expire_at {
            return Err(Error::ActionsNotAllowedError(format!(
                "parent key '{}' expire time is less than child key",
                parent_key.name
            )));
        }
        if data.key_type == X509ICA && parent_key.key_type != X509CA {
            return Err(Error::ActionsNotAllowedError(
                "only CA key is allowed for creating ICA".to_string(),
            ));
        }
        if data.key_type == X509EE && parent_key.key_type != X509ICA {
            return Err(Error::ActionsNotAllowedError(
                "only ICA key is allowed for creating End Entity Key".to_string(),
            ));
        }
        if data.key_type == X509CA || data.key_type == OpenPGP {
            return Err(Error::ActionsNotAllowedError(
                "CA key or openPGP is not allowed to specify parent key".to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<R, S> KeyService for DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static,
{
    async fn create(&self, user: UserIdentity, data: &mut DataKey) -> Result<DataKey> {
        //check parent key is enabled,expire time is greater than child key and hierarchy is correct
        if let Some(parent_id) = data.parent_id {
            self.check_key_hierarchy(user, data, parent_id).await?;
        }
        //check datakey existence
        if self
            .repository
            .get_by_id_or_name(None, Some(data.name.clone()), true)
            .await
            .is_ok()
        {
            return Err(Error::ParameterError(format!(
                "datakey '{}' already exists",
                data.name
            )));
        }
        //we need to create a key in database first, then generate sensitive data
        let mut key = self.repository.create(data.clone()).await?;
        match self.sign_service.read().await.generate_keys(&mut key).await {
            Ok(_) => {
                self.repository.update_key_data(key.clone()).await?;
                Ok(key)
            }
            Err(e) => {
                self.repository.delete(key.id).await?;
                Err(e)
            }
        }
    }

    async fn import(&self, data: &mut DataKey) -> Result<DataKey> {
        self.sign_service
            .read()
            .await
            .validate_and_update(data)
            .await?;
        self.repository.create(data.clone()).await
    }

    async fn get_raw_key_by_name(&self, name: &str) -> Result<DataKey> {
        self.repository
            .get_by_id_or_name(None, Some(name.to_owned()), true)
            .await
    }

    async fn get_all(&self, user_id: i32, query: DatakeyPaginationQuery) -> Result<PagedDatakey> {
        self.repository.get_keys_by_condition(user_id, query).await
    }

    async fn get_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey> {
        let datakey = self
            .get_and_check_permission(user, id_or_name, KeyAction::Read, false)
            .await?;
        Ok(datakey)
    }

    async fn export_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey> {
        //NOTE: since the public key or certificate basically will not change at all, we will cache the key here.
        if let Some(datakey) = self.container.get_read_datakey(&id_or_name).await {
            return Ok(datakey);
        }
        let mut key = self
            .get_and_check_permission(user, id_or_name.clone(), KeyAction::Read, true)
            .await?;
        self.sign_service
            .read()
            .await
            .decode_public_keys(&mut key)
            .await?;
        self.container
            .update_read_datakey(&id_or_name, key.clone())
            .await?;
        Ok(key)
    }

    async fn get_inner_one(&self, id_name: String) -> Result<DataKey> {
        //NOTE: since the public key or certificate basically will not change at all, we will cache the key here.
        if let Some(datakey) = self.container.get_read_datakey(&id_name).await {
            return Ok(datakey);
        }
        let id_or_name = id_name.parse::<i32>();
        let mut key: DataKey = match id_or_name {
            Ok(id_or_name) => {
                self.repository
                    .get_by_id_or_name(Some(id_or_name), None, false)
                    .await?
            }
            Err(_) => {
                self.repository
                    .get_by_id_or_name(None, Some(id_name.clone()), false)
                    .await?
            }
        };
        self.sign_service
            .read()
            .await
            .decode_public_keys(&mut key)
            .await?;
        self.container
            .update_read_datakey(&id_name, key.clone())
            .await?;
        Ok(key)
    }

    async fn export_cert_crl(
        &self,
        user: Option<UserIdentity>,
        id_or_name: String,
    ) -> Result<X509CRL> {
        let key = self
            .get_and_check_permission(user, id_or_name, KeyAction::Read, true)
            .await?;
        let crl = self.repository.get_x509_crl_by_ca_id(key.id).await?;
        Ok(crl)
    }

    async fn request_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let user_email = user.email.clone();
        let key = self
            .get_and_check_permission(Some(user), id_or_name, KeyAction::Delete, true)
            .await?;
        //check if the ca/ica key is used by other keys
        if key.key_type == KeyType::X509ICA || key.key_type == KeyType::X509CA {
            let children = self.repository.get_by_parent_id(key.id).await?;
            if !children.is_empty() {
                return Err(Error::ActionsNotAllowedError(format!(
                    "key '{}' is used by other keys, request delete is not allowed",
                    key.name
                )));
            }
        }
        self.repository
            .request_delete_key(
                user_id,
                user_email,
                key.id,
                key.visibility == Visibility::Public,
            )
            .await
    }

    async fn cancel_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let key = self
            .get_and_check_permission(Some(user), id_or_name, KeyAction::CancelDelete, true)
            .await?;
        self.repository.cancel_delete_key(user_id, key.id).await
    }

    async fn request_revoke(
        &self,
        user: UserIdentity,
        id_or_name: String,
        reason: X509RevokeReason,
    ) -> Result<()> {
        let user_id = user.id;
        let user_email = user.email.clone();
        let key = self
            .get_and_check_permission(Some(user), id_or_name, KeyAction::Revoke, true)
            .await?;
        self.repository
            .request_revoke_key(
                user_id,
                user_email,
                key.id,
                key.parent_id.unwrap(),
                reason,
                key.visibility == Visibility::Public,
            )
            .await?;
        Ok(())
    }

    async fn cancel_revoke(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let key = self
            .get_and_check_permission(Some(user), id_or_name, KeyAction::CancelRevoke, true)
            .await?;
        self.repository
            .cancel_revoke_key(user_id, key.id, key.parent_id.unwrap())
            .await?;
        Ok(())
    }

    async fn enable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()> {
        let key = self
            .get_and_check_permission(user, id_or_name, KeyAction::Enable, true)
            .await?;
        self.repository
            .update_state(key.id, KeyState::Enabled)
            .await
    }

    async fn disable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()> {
        let key = self
            .get_and_check_permission(user, id_or_name, KeyAction::Disable, true)
            .await?;
        self.repository
            .update_state(key.id, KeyState::Disabled)
            .await
    }

    async fn sign(
        &self,
        key_type: String,
        key_name: String,
        options: &HashMap<String, String>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut timekey: Option<DataKey> = None;
        if let Some(timestamp_key) = options.get(options::TIMESTAMP_KEY) {
            if !timestamp_key.is_empty() {
                timekey = Some(
                    self.get_timestamp_key_by_type_and_name(None, timestamp_key.to_string())
                        .await?,
                );
            }
        }
        let datakey = self.get_by_type_and_name(Some(key_type), key_name).await?;
        self.sign_service
            .read()
            .await
            .sign(&datakey, timekey, data, options.clone())
            .await
    }

    async fn get_by_type_and_name(
        &self,
        key_type: Option<String>,
        key_name: String,
    ) -> Result<DataKey> {
        if let Some(datakey) = self.container.get_sign_datakey(&key_name).await {
            return Ok(datakey);
        }
        let key = self
            .repository
            .get_enabled_key_by_type_and_name_with_parent_key(key_type, key_name.clone())
            .await?;
        self.container
            .update_sign_datakey(&key_name, key.clone())
            .await?;
        Ok(key)
    }

    async fn get_timestamp_key_by_type_and_name(
        &self,
        key_type: Option<String>,
        key_name: String,
    ) -> Result<DataKey> {
        if let Some(datakey) = self.timestamp_container.get_sign_datakey(&key_name).await {
            return Ok(datakey);
        }
        let key = self
            .repository
            .get_enabled_key_by_type_and_name_with_parent_key(key_type, key_name.clone())
            .await?;
        self.timestamp_container
            .update_sign_datakey(&key_name, key.clone())
            .await?;
        Ok(key)
    }

    fn start_key_rotate_loop(&self, cancel_token: CancellationToken) -> Result<()> {
        let sign_service = self.sign_service.clone();
        let mut interval = time::interval(Duration::seconds(60 * 60 * 2).to_std()?);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("start to rotate the keys");
                        match sign_service.write().await.rotate_key().await {
                            Ok(changed) => {
                                if changed {
                                    info!("keys has been successfully rotated");
                                }
                            }
                            Err(e) => {
                                error!("failed to rotate key: {}", e);
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        info!("cancel token received, will quit key rotate loop");
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    fn start_key_plugin_maintenance(
        &self,
        cancel_token: CancellationToken,
        refresh_days: i32,
    ) -> Result<()> {
        let mut interval = time::interval(Duration::hours(2).to_std()?);
        let duration = Duration::days(refresh_days as i64);
        let repository = self.repository.clone();
        let sign_service = self.sign_service.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                _ = interval.tick() => {
                    info!("start to update execute key plugin maintenance");
                    match repository.get_keys_for_crl_update(duration).await {
                        Ok(keys) => {
                            let now = Utc::now();
                            for key in keys {
                                match repository.get_revoked_serial_number_by_parent_id(key.id).await {
                                    Ok(revoke_keys) => {
                                        match sign_service.read().await.generate_crl_content(&key, revoke_keys, now, now + duration).await {
                                            Ok(data) => {
                                                let crl_content = X509CRL::new(key.id, data, now, now);
                                                if let Err(e) = repository.upsert_x509_crl(crl_content).await {
                                                    error!("Failed to update CRL content for key: {} {}, {}", key.key_state, key.id, e);
                                                } else {
                                                    info!("CRL has been successfully updated for key: {} {}", key.key_type, key.id);
                                                }}
                                            Err(e) => {
                                                error!("failed to update CRL content for key: {} {} and error {}", key.key_state, key.id, e);
                                            }}}
                                    Err(e) => {
                                        error!("failed to get revoked keys for key {} {}, error {}", key.key_state, key.id, e);
                                    }}}}
                        Err(e) => {
                            error!("failed to get keys for CRL update: {}", e);
                        }}}
                _ = cancel_token.cancelled() => {
                    info!("cancel token received, will quit key plugin maintenance loop");
                    break;
                }}
            }
        });
        Ok(())
    }

    #[cfg(not(feature = "cert_expirtion_check"))]
    fn start_cert_validity_period_check(
        &self,
        _domain: String,
        _adress: String,
        _topic: String,
    ) -> Result<()> {
        Ok(())
    }
    #[cfg(feature = "cert_expirtion_check")]
    fn start_cert_validity_period_check(
        &self,
        domain: String,
        adress: String,
        topic: String,
    ) -> Result<()> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", adress.to_string())
            .set("acks", "all")
            .create()
            .map_err(|e| Error::FrameworkError(format!("producer creation error: {e}")))?;
        let mut ticker = time::interval(Duration::minutes(24 * 60).to_std()?);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let repository = self.repository.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        info!("start to check certificate period");
                        let mut expire_key_list = Vec::<DataKey>::new();
                        match repository.get_all_keys().await {
                            Ok(keys) => {
                                for key in keys.data {
                                    let now: DateTime<Utc> = Utc::now();
                                    if now > key.expire_at - chrono::Duration::hours(24 * 30) {
                                        info!("cert {} will exipred at {}", key.name, key.expire_at);
                                        expire_key_list.push(key);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("failed to get keys: {}", e);
                            }
                        };
                        if expire_key_list.len() > 0 {
                            let json = match generate_cert_expire_json(expire_key_list, domain.to_string()) {
                                Ok(json) => json,
                                Err(e) => {
                                    error!("failed to generate_cert_expire_json: {}", e);
                                    continue;
                                }
                            };
                            let res = producer.send(
                                    FutureRecord::to(&topic.to_string()).key("").payload(&json),
                                    std::time::Duration::from_secs(10),
                            ).await;
                            match res {
                                Ok((partition, offset)) => {
                                    info!("delivered: partition={partition}, offset={offset}");
                                }
                                Err((e, _msg)) => {
                                    error!("delivery failed: {e}");
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::datakey::entity::DataKey;
    use chrono::{NaiveDate, TimeZone, Utc};
    fn create_test_data() -> Vec<DataKey> {
        let naive_datetime = NaiveDate::from_ymd_opt(2024, 6, 1)
            .and_then(|date| date.and_hms_opt(12, 0, 0))
            .expect("Invalid date or time");
        vec![
            DataKey {
                id: 1,
                name: "cert1".to_string(),
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
                create_at: Utc.from_utc_datetime(&naive_datetime),
                expire_at: Utc.from_utc_datetime(&naive_datetime),
                key_state: KeyState::Disabled,
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                parent_key: None,
            },
            DataKey {
                id: 2,
                name: "cert2".to_string(),
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
                create_at: Utc.from_utc_datetime(&naive_datetime),
                expire_at: Utc.from_utc_datetime(&naive_datetime),
                key_state: KeyState::Disabled,
                user_email: None,
                request_delete_users: None,
                request_revoke_users: None,
                parent_key: None,
            },
        ]
    }

    #[test]
    fn test_generate_cert_expire_json() {
        let keys = create_test_data();
        let domain = "example.com".to_string();
        let result = generate_cert_expire_json(keys, domain.clone());
        assert!(result.is_ok());
        let json = result.unwrap();
        let expected_json = r#"{
  "domain": "example.com",
  "expired_certs": [
    {
      "name": "cert1",
      "expire_at": "2024-06-01 12:00:00 UTC"
    },
    {
      "name": "cert2",
      "expire_at": "2024-06-01 12:00:00 UTC"
    }
  ]
}"#;
        assert_eq!(json, expected_json);
    }
}
