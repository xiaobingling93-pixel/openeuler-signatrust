/*
 *
 *  * // Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use super::traits::FileHandler;
use crate::util::attributes::PkeyHashAlgo;
use crate::util::error::{Error, Result};
use crate::util::options;
use crate::util::sign::{KeyType, SignType};
use async_trait::async_trait;
use openssl::hash::hash;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

const CMS_EXTENSION: &str = "p7s";

#[derive(Clone)]
pub struct CmsFileHandler {}

impl CmsFileHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl FileHandler for CmsFileHandler {
    fn validate_options(&self, sign_options: &mut HashMap<String, String>) -> Result<()> {
        if let Some(detached) = sign_options.get(options::DETACHED) {
            if detached == "false" {
                return Err(Error::InvalidArgumentError(
                    "p7s only support detached signature".to_string(),
                ));
            }
        }

        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509EE.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "p7s only support x509 key".to_string(),
                ));
            }
        }

        if let Some(sign_type) = sign_options.get(options::SIGN_TYPE) {
            if sign_type != SignType::Cms.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "p7s file only support cms".to_string(),
                ));
            }
        }
        Ok(())
    }

    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        _sign_options: &HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        fs::write(temp_file.clone(), &data[0]).await?;
        Ok((
            temp_file.as_path().display().to_string(),
            format!("{}.{}", path.as_path().display(), CMS_EXTENSION),
        ))
    }

    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
        key_attributes: &HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        let content = fs::read(path).await?;
        let digest_algo = PkeyHashAlgo::get_digest_algo_from_attributes(key_attributes);
        let digest = hash(digest_algo, &content)?;
        Ok(vec![digest.to_vec()])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

    #[test]
    fn test_validate_options() {
        let mut options = HashMap::new();
        options.insert(options::DETACHED.to_string(), "false".to_string());
        let handler = CmsFileHandler::new();
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: p7s only support detached signature"
        );

        options.insert(options::DETACHED.to_string(), "true".to_string());
        options.insert(options::KEY_TYPE.to_string(), KeyType::Pgp.to_string());
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: p7s only support x509 key"
        );

        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        options.insert(
            options::SIGN_TYPE.to_string(),
            SignType::RsaHash.to_string(),
        );
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: p7s file only support cms"
        );
        options.insert(options::SIGN_TYPE.to_string(), SignType::Cms.to_string());
        let result = handler.validate_options(&mut options);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_assemble_data() {
        let handler = CmsFileHandler::new();
        let options = HashMap::new();
        let path = PathBuf::from("./test_data/test.txt");
        let data = vec![vec![1, 2, 3]];
        let temp_dir = env::temp_dir();
        let result = handler
            .assemble_data(&path, data, &temp_dir, &options, &HashMap::new())
            .await;
        assert!(result.is_ok());
        let (temp_file, file_name) = result.expect("invoke assemble data should work");
        assert_eq!(temp_file.starts_with(temp_dir.to_str().unwrap()), true);
        assert_eq!(file_name, "./test_data/test.txt.p7s");
    }
}
