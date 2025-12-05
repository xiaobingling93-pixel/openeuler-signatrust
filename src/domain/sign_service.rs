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

use crate::util::error::{Error, Result};
use std::collections::HashMap;
use std::str::FromStr;

use crate::domain::datakey::entity::{DataKey, RevokedKey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq)]
pub enum SignBackendType {
    Memory,
}

impl FromStr for SignBackendType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "memory" => Ok(SignBackendType::Memory),
            _ => Err(Error::UnsupportedTypeError(format!(
                "{} sign backend type",
                s
            ))),
        }
    }
}

#[async_trait]
pub trait SignBackend: Send + Sync {
    async fn validate_and_update(&self, data_key: &mut DataKey) -> Result<()>;
    async fn generate_keys(&self, data_key: &mut DataKey) -> Result<()>;
    async fn rotate_key(&mut self) -> Result<bool>;
    async fn sign(
        &self,
        data_key: &DataKey,
        timestamp_key: Option<DataKey>,
        content: Vec<u8>,
        options: HashMap<String, String>,
    ) -> Result<Vec<u8>>;
    async fn decode_public_keys(&self, data_key: &mut DataKey) -> Result<()>;
    async fn decode_private_keys(&self, data_key: &mut DataKey) -> Result<()>;
    async fn generate_crl_content(
        &self,
        data_key: &DataKey,
        revoked_keys: Vec<RevokedKey>,
        last_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_backend_type_from_string_and_display() {
        let _ = SignBackendType::from_str("invalid_type")
            .expect_err("sign backend type from invalid string should fail");
        let sign_backend_type =
            SignBackendType::from_str("memory").expect("sign backend type from string failed");
        assert_eq!(sign_backend_type, SignBackendType::Memory);
    }
}
