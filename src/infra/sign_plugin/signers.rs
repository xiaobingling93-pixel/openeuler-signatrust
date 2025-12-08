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

use crate::domain::datakey::entity::{DataKey, KeyType};
use crate::domain::sign_plugin::SignPlugins;
use crate::infra::sign_plugin::openpgp::OpenPGPPlugin;
use crate::infra::sign_plugin::x509::X509Plugin;
use crate::util::error::Result;

use crate::domain::datakey::entity::SecDataKey;

pub struct Signers {}

impl Signers {
    //get responding sign plugin for data signing
    pub fn load_from_data_key(
        key_type: &KeyType,
        data_key: SecDataKey,
        timestamp_key: Option<SecDataKey>,
    ) -> Result<Box<dyn SignPlugins>> {
        match key_type {
            KeyType::OpenPGP => Ok(Box::new(OpenPGPPlugin::new(data_key, None)?)),
            KeyType::X509CA | KeyType::X509ICA | KeyType::X509EE => {
                Ok(Box::new(X509Plugin::new(data_key, timestamp_key)?))
            }
        }
    }

    pub fn validate_and_update(datakey: &mut DataKey) -> Result<()> {
        match datakey.key_type {
            KeyType::OpenPGP => OpenPGPPlugin::validate_and_update(datakey),
            KeyType::X509CA | KeyType::X509ICA | KeyType::X509EE => {
                X509Plugin::validate_and_update(datakey)
            }
        }
    }
}
