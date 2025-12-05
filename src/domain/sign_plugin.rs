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

use crate::domain::datakey::entity::{DataKey, DataKeyContent, KeyType, RevokedKey, SecDataKey};
use crate::util::error::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub trait SignPlugins: Send + Sync {
    fn new(db: SecDataKey, timestamp_key: Option<SecDataKey>) -> Result<Self>
    where
        Self: Sized;
    fn validate_and_update(key: &mut DataKey) -> Result<()>
    where
        Self: Sized;
    fn parse_attributes(
        private_key: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        certificate: Option<Vec<u8>>,
    ) -> HashMap<String, String>
    where
        Self: Sized;
    fn generate_keys(
        &self,
        key_type: &KeyType,
        infra_configs: &HashMap<String, String>,
    ) -> Result<DataKeyContent>;
    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>>;
    fn generate_crl_content(
        &self,
        revoked_keys: Vec<RevokedKey>,
        last_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>>;
}
