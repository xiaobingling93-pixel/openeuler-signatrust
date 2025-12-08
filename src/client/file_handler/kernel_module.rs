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

use super::traits::FileHandler;
use crate::util::error::Result;
use async_trait::async_trait;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str;

use bincode::{config, Decode, Encode};
use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::os::raw::{c_uchar, c_uint};
use uuid::Uuid;

use crate::util::error::Error;
use crate::util::options;
use crate::util::options::DETACHED;
use crate::util::sign::{KeyType, SignType};

const FILE_EXTENSION: &str = "p7s";
const PKEY_ID_PKCS7: c_uchar = 2;
const MAGIC_NUMBER: &str = "~Module signature appended~\n";
const MAGIC_NUMBER_SIZE: usize = 28;
const SIGNATURE_SIZE: usize = 40;

// Reference https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/scripts/sign-file.c
#[derive(Encode, Decode, PartialEq, Debug)]
struct ModuleSignature {
    algo: c_uchar,       /* Public-key crypto algorithm [0] */
    hash: c_uchar,       /* Digest algorithm [0] */
    id_type: c_uchar,    /* Key identifier type [PKEY_ID_PKCS7] */
    signer_len: c_uchar, /* Length of signer's name [0] */
    key_id_len: c_uchar, /* Length of key identifier [0] */
    _pad: [c_uchar; 3],
    sig_len: c_uint, /* Length of signature data */
}

impl ModuleSignature {
    fn new(length: c_uint) -> ModuleSignature {
        ModuleSignature {
            algo: 0,
            hash: 0,
            id_type: PKEY_ID_PKCS7,
            signer_len: 0,
            key_id_len: 0,
            _pad: [0, 0, 0],
            sig_len: length,
        }
    }
}

#[derive(Clone)]
pub struct KernelModuleFileHandler {}

impl KernelModuleFileHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub fn generate_detached_signature(&self, module: &str, signature: &[u8]) -> Result<()> {
        let mut buffer = std::fs::File::create(module)?;
        buffer.write_all(signature)?;
        Ok(())
    }

    pub fn append_inline_signature(
        &self,
        module: &PathBuf,
        tempfile: &PathBuf,
        signature: &[u8],
    ) -> Result<()> {
        let mut signed = fs::File::create(tempfile)?;
        signed.write_all(&self.get_raw_content(module, &HashMap::new())?)?;
        signed.write_all(signature)?;
        let sig_struct = ModuleSignature::new(signature.len() as c_uint);
        signed.write_all(&bincode::encode_to_vec(
            sig_struct,
            config::standard()
                .with_fixed_int_encoding()
                .with_big_endian(),
        )?)?;
        signed.write_all(MAGIC_NUMBER.as_bytes())?;
        Ok(())
    }

    pub fn get_raw_content(
        &self,
        path: &PathBuf,
        sign_options: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let raw_content = fs::read(path)?;
        let mut file = fs::File::open(path)?;
        if file.metadata()?.len() <= SIGNATURE_SIZE as u64 {
            return Ok(raw_content);
        }
        //identify magic string and end of the file
        file.seek(io::SeekFrom::End(-(MAGIC_NUMBER_SIZE as i64)))?;
        let mut signature_ending: [u8; MAGIC_NUMBER_SIZE] = [0; MAGIC_NUMBER_SIZE];
        let _ = file.read(&mut signature_ending)?;
        return match str::from_utf8(signature_ending.as_ref()) {
            Ok(ending) => {
                return if ending == MAGIC_NUMBER {
                    file.seek(io::SeekFrom::End(-(SIGNATURE_SIZE as i64)))?;
                    let mut signature_meta: [u8; SIGNATURE_SIZE - MAGIC_NUMBER_SIZE] =
                        [0; SIGNATURE_SIZE - MAGIC_NUMBER_SIZE];
                    let _ = file.read(&mut signature_meta)?;
                    //decode kernel module signature struct
                    let signature: ModuleSignature = bincode::decode_from_slice(
                        &signature_meta,
                        config::standard()
                            .with_fixed_int_encoding()
                            .with_big_endian(),
                    )?
                    .0;
                    if raw_content.len() < SIGNATURE_SIZE + signature.sig_len as usize {
                        return Err(Error::SplitFileError(
                            "invalid kernel module signature size found".to_owned(),
                        ));
                    }
                    if let Some(detached) = sign_options.get(DETACHED) {
                        if detached == "true" {
                            return Err(Error::SplitFileError(
                                "already signed kernel module file doesn't support detached signature".to_owned()));
                        }
                    }
                    //read raw content
                    Ok(raw_content
                        [0..(raw_content.len() - SIGNATURE_SIZE - signature.sig_len as usize)]
                        .to_owned())
                } else {
                    Ok(raw_content)
                };
            }
            Err(_) => {
                //try to read whole content
                Ok(raw_content)
            }
        };
    }
}

#[async_trait]
impl FileHandler for KernelModuleFileHandler {
    fn validate_options(&self, sign_options: &mut HashMap<String, String>) -> Result<()> {
        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509EE.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "kernel module file only support x509 signature".to_string(),
                ));
            }
        }

        if let Some(sign_type) = sign_options.get(options::SIGN_TYPE) {
            if sign_type != SignType::KernelCms.to_string().as_str()
                && sign_type != SignType::PKCS7.to_string().as_str()
            {
                return Err(Error::InvalidArgumentError(
                    "kernel module file only support kernel-cms or pkcs7 sign type".to_string(),
                ));
            }
        }
        sign_options.insert(
            options::INCLUDE_PARENT_CERT.to_string(),
            "false".to_string(),
        );
        Ok(())
    }

    //NOTE: if it's a signed kernel module file, detached option will lead to the failure of verification.
    async fn split_data(
        &self,
        path: &PathBuf,
        sign_options: &mut HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        Ok(vec![self.get_raw_content(path, sign_options)?])
    }

    /* when assemble generic signature when only create another .asc file separately */
    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        sign_options: &HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        //convert bytes into string
        if let Some(detached) = sign_options.get(DETACHED) {
            if detached == "true" {
                self.generate_detached_signature(&temp_file.display().to_string(), &data[0])?;
                return Ok((
                    temp_file.as_path().display().to_string(),
                    format!("{}.{}", path.display(), FILE_EXTENSION),
                ));
            }
        }
        self.append_inline_signature(path, &temp_file, &data[0])?;
        return Ok((
            temp_file.as_path().display().to_string(),
            path.display().to_string(),
        ));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::env;

    fn generate_signed_kernel_module(
        length: usize,
        incorrect_length: bool,
    ) -> Result<(String, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let temp_file = env::temp_dir().join(Uuid::new_v4().to_string());
        let mut file = fs::File::create(temp_file.clone())?;
        let raw_content: Vec<u8> = (0..length).map(|_| rng.gen_range(0..=255)).collect();
        file.write_all(&raw_content)?;
        //append fake signature
        let signature = vec![1, 2, 3, 4, 5, 6];
        file.write_all(&signature)?;
        let mut size = signature.len();
        if incorrect_length {
            size = size + length + 2;
        }
        //append signature metadata
        let signature = ModuleSignature::new(size as c_uint);
        file.write_all(&bincode::encode_to_vec(
            signature,
            config::standard()
                .with_fixed_int_encoding()
                .with_big_endian(),
        )?)?;
        file.write_all(MAGIC_NUMBER.as_bytes())?;
        Ok((temp_file.display().to_string(), raw_content))
    }

    fn generate_unsigned_kernel_module(length: usize) -> Result<(String, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let temp_file = env::temp_dir().join(Uuid::new_v4().to_string());
        let mut file = fs::File::create(temp_file.clone())?;
        let raw_content: Vec<u8> = (0..length).map(|_| rng.gen_range(0..=255)).collect();
        file.write_all(&raw_content)?;
        Ok((temp_file.display().to_string(), raw_content))
    }

    #[test]
    fn test_get_raw_content_with_small_unsigned_content() {
        let sign_options = HashMap::new();
        let file_handler = KernelModuleFileHandler::new();
        let (name, original_content) = generate_unsigned_kernel_module(SIGNATURE_SIZE - 1)
            .expect("generate unsigned kernel module failed");
        let path = PathBuf::from(name);
        let raw_content = file_handler
            .get_raw_content(&path, &sign_options)
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), SIGNATURE_SIZE - 1);
        assert_eq!(original_content, raw_content);
    }

    #[test]
    fn test_get_raw_content_with_large_unsigned_content() {
        let sign_options = HashMap::new();
        let file_handler = KernelModuleFileHandler::new();
        let (name, original_content) = generate_unsigned_kernel_module(SIGNATURE_SIZE + 100)
            .expect("generate unsigned kernel module failed");
        let path = PathBuf::from(name);
        let raw_content = file_handler
            .get_raw_content(&path, &sign_options)
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), SIGNATURE_SIZE + 100);
        assert_eq!(original_content, raw_content);
    }

    #[test]
    fn test_get_raw_content_with_signed_content() {
        let sign_options = HashMap::new();
        let file_handler = KernelModuleFileHandler::new();
        let (name, original_content) = generate_signed_kernel_module(100, false)
            .expect("generate signed kernel module failed");
        let path = PathBuf::from(name);
        let raw_content = file_handler
            .get_raw_content(&path, &sign_options)
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), 100);
        assert_eq!(original_content, raw_content);
    }

    #[test]
    fn test_get_raw_content_with_invalid_signed_content() {
        let sign_options = HashMap::new();
        let file_handler = KernelModuleFileHandler::new();
        let (name, _) =
            generate_signed_kernel_module(100, true).expect("generate signed kernel module failed");
        let path = PathBuf::from(name);
        let result = file_handler.get_raw_content(&path, &sign_options);
        assert_eq!(
            result.unwrap_err().to_string(),
            "failed to split file: invalid kernel module signature size found"
        );
    }

    #[test]
    fn test_validate_options() {
        let mut options = HashMap::new();
        options.insert(options::KEY_TYPE.to_string(), KeyType::Pgp.to_string());
        let handler = KernelModuleFileHandler::new();
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: kernel module file only support x509 signature"
        );

        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        options.insert(
            options::SIGN_TYPE.to_string(),
            SignType::Authenticode.to_string(),
        );
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: kernel module file only support kernel-cms or pkcs7 sign type"
        );

        options.insert(
            options::SIGN_TYPE.to_string(),
            SignType::KernelCms.to_string(),
        );
        let result = handler.validate_options(&mut options);
        assert!(result.is_ok());

        options.insert(options::SIGN_TYPE.to_string(), SignType::PKCS7.to_string());
        let result = handler.validate_options(&mut options);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_assemble_data_with_detached_true() {
        let handler = KernelModuleFileHandler::new();
        let mut options = HashMap::new();
        options.insert(options::DETACHED.to_string(), "true".to_string());
        let path = PathBuf::from("./test_data/test.ko");
        let data = vec![vec![1, 2, 3]];
        let temp_dir = env::temp_dir();
        let result = handler
            .assemble_data(&path, data, &temp_dir, &options, &HashMap::new())
            .await;
        assert!(result.is_ok());
        let (temp_file, file_name) = result.expect("invoke assemble data should work");
        assert_eq!(temp_file.starts_with(temp_dir.to_str().unwrap()), true);
        assert_eq!(file_name, "./test_data/test.ko.p7s");
        let result = fs::read(temp_file).expect("read temp file failed");
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_assemble_data_with_detached_false() {
        let handler = KernelModuleFileHandler::new();
        let mut options = HashMap::new();
        options.insert(DETACHED.to_string(), "false".to_string());
        let (name, raw_content) = generate_signed_kernel_module(100, false)
            .expect("generate signed kernel module failed");
        let path = PathBuf::from(name.clone());
        let data = vec![vec![1, 2, 3]];
        let temp_dir = env::temp_dir();
        let result = handler
            .assemble_data(&path, data, &temp_dir, &options, &HashMap::new())
            .await;
        assert!(result.is_ok());
        let (temp_file, file_name) = result.expect("invoke assemble data should work");
        assert_eq!(temp_file.starts_with(temp_dir.to_str().unwrap()), true);
        assert_eq!(file_name, name);
        let result = handler
            .get_raw_content(&PathBuf::from(temp_file), &options)
            .expect("get raw content failed");
        assert_eq!(result, raw_content);
    }

    #[tokio::test]
    async fn test_split_content() {
        let mut sign_options = HashMap::new();
        let file_handler = KernelModuleFileHandler::new();
        let (name, original_content) = generate_unsigned_kernel_module(SIGNATURE_SIZE - 1)
            .expect("generate unsigned kernel module failed");
        let path = PathBuf::from(name);
        let raw_content = file_handler
            .split_data(&path, &mut sign_options, &HashMap::new())
            .await
            .expect("get raw content failed");
        assert_eq!(raw_content[0].len(), SIGNATURE_SIZE - 1);
        assert_eq!(original_content, raw_content[0]);
    }
}
