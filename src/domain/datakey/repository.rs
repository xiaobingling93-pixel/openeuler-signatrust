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

use super::entity::DataKey;
use crate::domain::datakey::entity::{
    DatakeyPaginationQuery, KeyState, PagedDatakey, RevokedKey, X509RevokeReason, X509CRL,
};
use crate::util::error::Result;
use async_trait::async_trait;
use chrono::Duration;

#[async_trait]
pub trait Repository: Send + Sync {
    async fn create(&self, data_key: DataKey) -> Result<DataKey>;
    async fn delete(&self, id: i32) -> Result<()>;
    async fn get_all_keys(
        &self,
        user_id: i32,
        query: DatakeyPaginationQuery,
    ) -> Result<PagedDatakey>;
    async fn get_by_id_or_name(
        &self,
        id: Option<i32>,
        name: Option<String>,
        raw_datakey: bool,
    ) -> Result<DataKey>;
    async fn update_state(&self, id: i32, state: KeyState) -> Result<()>;
    async fn update_key_data(&self, data_key: DataKey) -> Result<()>;
    async fn get_enabled_key_by_type_and_name_with_parent_key(
        &self,
        key_type: Option<String>,
        name: String,
    ) -> Result<DataKey>;
    async fn request_delete_key(
        &self,
        user_id: i32,
        user_email: String,
        id: i32,
        public_key: bool,
    ) -> Result<()>;
    async fn request_revoke_key(
        &self,
        user_id: i32,
        user_email: String,
        id: i32,
        parent_id: i32,
        reason: X509RevokeReason,
        public_key: bool,
    ) -> Result<()>;
    async fn cancel_delete_key(&self, user_id: i32, id: i32) -> Result<()>;
    async fn cancel_revoke_key(&self, user_id: i32, id: i32, parent_id: i32) -> Result<()>;
    //crl related methods
    async fn get_x509_crl_by_ca_id(&self, id: i32) -> Result<X509CRL>;
    async fn upsert_x509_crl(&self, crl: X509CRL) -> Result<()>;
    async fn get_keys_for_crl_update(&self, duration: Duration) -> Result<Vec<DataKey>>;
    async fn get_revoked_serial_number_by_parent_id(&self, id: i32) -> Result<Vec<RevokedKey>>;
    async fn get_by_parent_id(&self, parent_id: i32) -> Result<Vec<DataKey>>;
}
