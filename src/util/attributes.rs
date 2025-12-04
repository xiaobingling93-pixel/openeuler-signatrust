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

use std::collections::HashMap;

use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Rsa;
use openssl_sys::{
    EVP_md5, EVP_sha1, EVP_sha224, EVP_sha256, EVP_sha384, EVP_sha512, EVP_sm3, EVP_MD,
};
pub const DIGEST_ALGO: &str = "digest_algorithm";

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PkeyHashAlgo {
    Md4 = 0,
    Md5 = 1,
    Sha1 = 2,
    RipeMd160 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Sha224 = 7,
    RipeMd128 = 8,
    RipeMd256 = 9,
    RipeMd320 = 10,
    Wp256 = 11,
    Wp384 = 12,
    Wp512 = 13,
    Tgr128 = 14,
    Tgr160 = 15,
    Tgr192 = 16,
    Sm3256 = 17,
    Streebog256 = 18,
    Streebog512 = 19,
}

impl PkeyHashAlgo {
    pub fn get_hash_algo_from_attributes(attributes: &HashMap<String, String>) -> PkeyHashAlgo {
        let hash_algo = match attributes
            .get(DIGEST_ALGO)
            .expect("get algo failed")
            .as_str()
        {
            "md5" => PkeyHashAlgo::Md5,
            "sha1" => PkeyHashAlgo::Sha1,
            "sha2_224" => PkeyHashAlgo::Sha224,
            "sha2_256" => PkeyHashAlgo::Sha256,
            "sha2_384" => PkeyHashAlgo::Sha384,
            "sha2_512" => PkeyHashAlgo::Sha512,
            _ => PkeyHashAlgo::Sha256,
        };
        hash_algo
    }

    pub fn get_digest_algo_from_attributes(attributes: &HashMap<String, String>) -> MessageDigest {
        let digest_algo = match attributes
            .get(DIGEST_ALGO)
            .expect("get algo failed")
            .as_str()
        {
            "md5" => MessageDigest::md5(),
            "sha1" => MessageDigest::sha1(),
            "sha2_224" => MessageDigest::sha224(),
            "sha2_256" => MessageDigest::sha256(),
            "sha2_384" => MessageDigest::sha384(),
            "sha2_512" => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        };
        digest_algo
    }

    pub fn get_openssl_c_digest_algo(digest: &String) -> *const EVP_MD {
        unsafe {
            let digest_algo = match digest.as_str() {
                "md5" => EVP_md5(),
                "sha1" => EVP_sha1(),
                "sha2_224" => EVP_sha224(),
                "sha2_256" => EVP_sha256(),
                "sha2_384" => EVP_sha384(),
                "sha2_512" => EVP_sha512(),
                "sm3" => EVP_sm3(),
                _ => EVP_sha256(),
            };
            digest_algo
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

pub fn do_sign_rsahash(
    pkey_input: &[u8],
    data: &[u8],
    attributes: &HashMap<String, String>,
    signature: &mut Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let digest_algo = match attributes
        .get(DIGEST_ALGO)
        .expect("get algo failed")
        .as_str()
    {
        "md5" => Md::md5(),
        "sha1" => Md::sha1(),
        "sha2_224" => Md::sha224(),
        "sha2_256" => Md::sha256(),
        "sha2_384" => Md::sha384(),
        "sha2_512" => Md::sha512(),
        _ => Md::sha256(),
    };
    let rsa = Rsa::private_key_from_pem(pkey_input).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut ctx = PkeyCtx::new(&pkey).unwrap();
    ctx.sign_init().unwrap();
    ctx.set_signature_md(digest_algo).unwrap();

    ctx.sign_to_vec(data, signature).unwrap();
    debug!(
        "Signature: {:?} hex::encode(): {:?}",
        signature,
        hex::encode(&signature)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::env;
    use std::fs::read;
    use std::panic;

    // 测试数据
    const TEST_DATA: &[u8] = b"Hello, world!";

    #[tokio::test]
    async fn test_attributes_do_sign_rsahash() {
        let attributes = HashMap::from([(DIGEST_ALGO.to_string(), "sha2_256".to_string())]);

        let result = panic::catch_unwind(|| async {
            let current_dir = env::current_dir().expect("get current dir failed");
            let signature_buf = read(current_dir.join("test_assets").join("private.pem")).unwrap();
            let mut signature = Vec::new();
            // 使用私钥进行签名
            let inner_result =
                do_sign_rsahash(&signature_buf, TEST_DATA, &attributes, &mut signature);
            print!("attribute_: {:?}\n", inner_result);
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_attributes_pkey_hash_algo_methods() {
        let attributes = HashMap::from([(DIGEST_ALGO.to_string(), "sha1".to_string())]);

        // 测试 get_hash_algo_from_attributes
        let hash_algo = PkeyHashAlgo::get_hash_algo_from_attributes(&attributes);
        assert_eq!(hash_algo, PkeyHashAlgo::Sha1);

        // 测试 get_digest_algo_from_attributes
        let digest_algo = PkeyHashAlgo::get_digest_algo_from_attributes(&attributes);
        assert_eq!(digest_algo.block_size(), 64);

        // 测试 to_u8
        let u8_value = hash_algo.to_u8();
        assert_eq!(u8_value, 2); // Sha1 对应的值是 2
    }
}
