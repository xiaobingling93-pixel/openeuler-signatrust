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

use std::collections::HashMap;

use crate::domain::sign_service::SignBackend;
use std::sync::Arc;

use config::Config;
use std::sync::RwLock;

use crate::domain::datakey::entity::DataKey;
use crate::domain::datakey::entity::{RevokedKey, SecDataKey, INFRA_CONFIG_DOMAIN_NAME};
use crate::domain::encryption_engine::EncryptionEngine;
use crate::infra::database::model::clusterkey::repository;
use crate::infra::encryption::algorithm::factory::AlgorithmFactory;
use crate::infra::encryption::engine::EncryptionEngineWithClusterKey;
use crate::infra::kms::factory;
use crate::infra::sign_plugin::signers::Signers;
use crate::util::error::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;

/// Memory Sign Backend will perform all sensitive operations directly in host memory.
pub struct MemorySignBackend {
    server_config: Arc<RwLock<Config>>,
    engine: Box<dyn EncryptionEngine>,
    infra_configs: HashMap<String, String>,
}

impl MemorySignBackend {
    /// initialize process
    /// 1. initialize the kms provider
    /// 2. initialize the cluster repo
    /// 2. initialize the encryption engine including the cluster key
    /// 3. initialize the signing plugins
    pub async fn new(
        server_config: Arc<RwLock<Config>>,
        db_connection: &'static DatabaseConnection,
    ) -> Result<MemorySignBackend> {
        //initialize the kms backend
        let kms_provider = factory::KMSProviderFactory::new_provider(
            &server_config.read()?.get_table("memory.kms-provider")?,
        )?;
        let repository = repository::ClusterKeyRepository::new(db_connection);
        let engine_config = server_config
            .read()?
            .get_table("memory.encryption-engine")?;
        let encryptor = AlgorithmFactory::new_algorithm(
            &engine_config
                .get("algorithm")
                .expect("encryption engine should configured")
                .to_string(),
        )?;
        let mut engine = EncryptionEngineWithClusterKey::new(
            repository,
            encryptor,
            &engine_config,
            kms_provider,
        )?;
        engine.initialize().await?;

        let infra_configs = HashMap::from([(
            INFRA_CONFIG_DOMAIN_NAME.to_string(),
            server_config
                .read()?
                .get_string("control-server.domain_name")?,
        )]);

        Ok(MemorySignBackend {
            server_config,
            infra_configs,
            engine: Box::new(engine),
        })
    }
}

#[async_trait]
impl SignBackend for MemorySignBackend {
    async fn validate_and_update(&self, data_key: &mut DataKey) -> Result<()> {
        if let Err(err) = Signers::validate_and_update(data_key) {
            return Err(Error::ParameterError(format!(
                "failed to validate imported key content: {}",
                err
            )));
        }
        data_key.private_key = self.engine.encode(data_key.private_key.clone()).await?;
        data_key.public_key = self.engine.encode(data_key.public_key.clone()).await?;
        data_key.certificate = self.engine.encode(data_key.certificate.clone()).await?;
        Ok(())
    }

    async fn generate_keys(&self, data_key: &mut DataKey) -> Result<()> {
        let sec_key = SecDataKey::load(data_key, &self.engine).await?;
        let content = Signers::load_from_data_key(&data_key.key_type, sec_key, None)?
            .generate_keys(&data_key.key_type, &self.infra_configs)?;
        data_key.private_key = self.engine.encode(content.private_key).await?;
        data_key.public_key = self.engine.encode(content.public_key).await?;
        data_key.certificate = self.engine.encode(content.certificate).await?;
        data_key.fingerprint = content.fingerprint;
        data_key.serial_number = content.serial_number;
        Ok(())
    }

    async fn rotate_key(&mut self) -> Result<bool> {
        self.engine.rotate_key().await
    }

    async fn sign(
        &self,
        data_key: &DataKey,
        timestamp_key: Option<DataKey>,
        content: Vec<u8>,
        options: HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let sec_key = SecDataKey::load(data_key, &self.engine).await?;
        let mut timestamp_sec_key: Option<SecDataKey> = None;
        if let Some(ref key) = timestamp_key {
            timestamp_sec_key = Some(SecDataKey::load(&key, &self.engine).await?);
        }
        Signers::load_from_data_key(&data_key.key_type, sec_key, timestamp_sec_key)?
            .sign(content, options)
    }

    async fn decode_public_keys(&self, data_key: &mut DataKey) -> Result<()> {
        data_key.public_key = self.engine.decode(data_key.public_key.clone()).await?;
        data_key.certificate = self.engine.decode(data_key.certificate.clone()).await?;
        Ok(())
    }

    async fn decode_private_keys(&self, data_key: &mut DataKey) -> Result<()> {
        data_key.private_key = self.engine.decode(data_key.private_key.clone()).await?;
        data_key.certificate = self.engine.decode(data_key.certificate.clone()).await?;
        Ok(())
    }

    async fn generate_crl_content(
        &self,
        data_key: &DataKey,
        revoked_keys: Vec<RevokedKey>,
        last_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        let sec_key = SecDataKey::load(data_key, &self.engine).await?;
        Signers::load_from_data_key(&data_key.key_type, sec_key, None)?.generate_crl_content(
            revoked_keys,
            last_update,
            next_update,
        )
    }
}
