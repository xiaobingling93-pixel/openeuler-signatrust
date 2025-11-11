/*
 *
 *  * // Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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
use crate::util::error::Result;
use crate::util::sign::{KeyType, SignType};
use async_trait::async_trait;
use std::io::Write;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

use crate::util::attributes::PkeyHashAlgo;
use crate::util::error::Error;
use crate::util::options;
use openssl::hash::hash;
use std::collections::HashMap;

const FILE_EXTENSION: &str = "sig";
const SUBJECT_KEY_ID: &str = "subject_key";
const KEY_ID_LEN: &usize = &4;

#[derive(Clone)]
pub struct ImaFileHandler {}

impl ImaFileHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
struct ImaV2Hdr {
    magic: u8,     // magic number is 3
    version: u8,   // version number is 2
    hash_algo: u8, // hash algorithm sha256 is 4
    keyid: u32,    // Subject Key Identifier（SKID）
    sig_size: u16,
    sig: Vec<u8>,
}

impl ImaV2Hdr {
    fn new(algo: u8, keyid: u32, sig: &Vec<u8>) -> Self {
        ImaV2Hdr {
            magic: 3,
            version: 2,
            hash_algo: algo,
            keyid,
            sig_size: sig.len() as u16,
            sig: sig.clone(), // Clone the vector inside the struct
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.magic);
        bytes.push(self.version);
        bytes.push(self.hash_algo);
        bytes.extend_from_slice(&self.keyid.to_le_bytes());
        bytes.extend_from_slice(&self.sig_size.to_be_bytes()); // sig_size is big-endian
        bytes.extend_from_slice(&self.sig);
        bytes
    }
}

#[async_trait]
impl FileHandler for ImaFileHandler {
    fn validate_options(&self, sign_options: &mut HashMap<String, String>) -> Result<()> {
        if let Some(detached) = sign_options.get(options::DETACHED) {
            if detached == "false" {
                return Err(Error::InvalidArgumentError(
                    "ima signer only support detached signature, you may need add the --detach argument".to_string(),
                ));
            }
        }
        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509EE.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "ima signer only support x509 key type".to_string(),
                ));
            }
        }
        if let Some(sign_type) = sign_options.get(options::SIGN_TYPE) {
            if sign_type != SignType::RsaHash.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "ima evm file only support rsahash sign type".to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        let content = fs::read(path).await?;
        debug!("key_attributes: {:?}", _key_attributes);
        let digest_algo = PkeyHashAlgo::get_digest_algo_from_attributes(_key_attributes);
        let digest = hash(digest_algo, &content)?; // 完成哈希计算并获取结果

        Ok(vec![digest.to_vec()])
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
        let skid = _key_attributes
            .get(SUBJECT_KEY_ID)
            .expect("get skid failed");
        let key_id = match hex::decode(skid) {
            Ok(subject_id) => subject_id[subject_id.len() - KEY_ID_LEN..].to_vec(),
            Err(e) => return Err(Error::ConvertError(format!("{:?}", e))),
        };
        debug!("skid: {:?}， key_id {:x?}", skid.clone(), key_id);
        let hash_algo = PkeyHashAlgo::get_hash_algo_from_attributes(_key_attributes);
        let hdr = ImaV2Hdr::new(
            hash_algo.to_u8(),
            u32::from_le_bytes(
                key_id
                    .try_into()
                    .unwrap_or_else(|_| panic!("Expected a vector of length 4")),
            ),
            &data[0],
        );

        //convert bytes into string
        let mut signed = std::fs::File::create(&temp_file)?;

        signed.write_all(&hdr.serialize())?;
        Ok((
            temp_file.as_path().display().to_string(),
            format!("{}.{}", path.as_path().display(), FILE_EXTENSION),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{domain::datakey::plugins::x509::X509DigestAlgorithm, util::attributes};

    use super::*;
    use std::collections::HashMap;
    use std::panic;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ima_validate_options() {
        let handler: ImaFileHandler = ImaFileHandler::new();
        let mut options = HashMap::new();
        options.insert(String::from(options::DETACHED), String::from("true"));
        options.insert(String::from(options::KEY_TYPE), KeyType::X509EE.to_string());
        options.insert(
            String::from(options::SIGN_TYPE),
            SignType::RsaHash.to_string(),
        );

        assert!(handler.validate_options(&mut options).is_ok());

        options.insert(String::from(options::DETACHED), String::from("false"));
        assert!(handler.validate_options(&mut options).is_err());
    }

    #[tokio::test]
    async fn test_ima_split_data() {
        let handler: ImaFileHandler = ImaFileHandler::new();
        let temp_file = TempDir::new().unwrap();
        let path = temp_file.path().join("test_file");
        fs::write(&path, b"test data").await.unwrap();

        let result = panic::catch_unwind(|| async {
            let inner_result = handler
                .split_data(&path, &mut HashMap::new(), &HashMap::new())
                .await;
            print!("attribute_: {:?}\n", inner_result);
        });

        assert!(result.is_ok());

        let mut attribute_ = HashMap::new();
        attribute_.insert(
            String::from(attributes::DIGEST_ALGO),
            X509DigestAlgorithm::SHA2_256.to_string(),
        );
        print!("attribute_: {:?}\n", attribute_);

        let result = handler
            .split_data(&path, &mut HashMap::new(), &attribute_)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ima_assemble_data() {
        let handler: ImaFileHandler = ImaFileHandler::new();
        let temp_dir = TempDir::new().unwrap();
        let path = PathBuf::from("/tmp/test");
        let data = vec![vec![1, 2, 3, 4, 5]];
        let result = panic::catch_unwind(|| async {
            let inner_result = handler
                .assemble_data(
                    &path,
                    data,
                    &temp_dir.path().to_path_buf(),
                    &HashMap::new(),
                    &HashMap::new(),
                )
                .await;
            print!("attribute_: {:?}\n", inner_result);
        });
        assert!(result.is_ok());

        let data = vec![vec![1, 2, 3, 4, 5]];
        let mut attribute_ = HashMap::new();
        attribute_.insert(String::from(SUBJECT_KEY_ID), "0982347ddcf4323d".to_string());
        attribute_.insert(
            String::from(attributes::DIGEST_ALGO),
            X509DigestAlgorithm::SHA2_256.to_string(),
        );
        let result = handler
            .assemble_data(
                &path,
                data,
                &temp_dir.path().to_path_buf(),
                &HashMap::new(),
                &attribute_,
            )
            .await;
        print!("result: {:?}\n", result);
        assert!(result.is_ok());

        let data = vec![vec![1, 2, 3, 4, 5]];
        let mut attribute_ = HashMap::new();
        // error subject key id data
        attribute_.insert(
            String::from(SUBJECT_KEY_ID),
            "0982347ddcf4323dnn".to_string(),
        );
        attribute_.insert(
            String::from(attributes::DIGEST_ALGO),
            X509DigestAlgorithm::SHA2_256.to_string(),
        );
        let result = handler
            .assemble_data(
                &path,
                data,
                &temp_dir.path().to_path_buf(),
                &HashMap::new(),
                &attribute_,
            )
            .await;
        print!("result: {:?}\n", result);
        assert!(result.is_err());
    }
}
