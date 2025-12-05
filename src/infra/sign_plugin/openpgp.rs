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

use crate::domain::sign_plugin::SignPlugins;

use crate::util::error::{Error, Result};
use crate::util::options;
use chrono::{DateTime, Utc};
use pgp::composed::key::SecretKeyParamsBuilder;
use pgp::composed::signed_key::{SignedPublicKey, SignedSecretKey};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::packet::SignatureConfig;
use pgp::packet::*;
use pgp::packet::{Subpacket, SubpacketData};

use super::util::{attributes_validate, validate_utc_time, validate_utc_time_not_expire};
use crate::domain::datakey::entity::{
    DataKey, DataKeyContent, KeyType as EntityKeyType, RevokedKey, SecDataKey,
};
use crate::domain::datakey::plugins::openpgp::{
    OpenPGPDigestAlgorithm, OpenPGPKeyType, PGP_VALID_KEY_SIZE,
};
use crate::util::key::encode_u8_to_hex_string;
#[allow(unused_imports)]
use enum_iterator::all;
use pgp::composed::StandaloneSignature;
use pgp::types::KeyTrait;
use pgp::types::{CompressionAlgorithm, SecretKeyTrait};
use pgp::Deserializable;
use serde::Deserialize;
use smallvec::*;
use std::collections::HashMap;
use std::io::Cursor;
use std::str::from_utf8;
use std::str::FromStr;
use validator::{Validate, ValidationError};

#[derive(Debug, Validate, Deserialize)]
pub struct PgpKeyImportParameter {
    key_type: OpenPGPKeyType,
    #[validate(custom(
        function = "validate_key_size",
        message = "invalid openpgp attribute 'key_length'"
    ))]
    key_length: Option<String>,
    digest_algorithm: OpenPGPDigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid openpgp attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid openpgp attribute 'expire_at'"
    ))]
    expire_at: String,
    passphrase: Option<String>,
}

#[derive(Debug, Validate, Deserialize)]
pub struct PgpKeyGenerationParameter {
    #[validate(length(min = 4, max = 100, message = "invalid openpgp attribute 'name'"))]
    name: String,
    // email format validation is disabled due to copr has the case of group prefixed email: `@group#project@copr.com`
    #[validate(length(min = 2, max = 100, message = "invalid openpgp attribute 'email'"))]
    email: String,
    key_type: OpenPGPKeyType,
    #[validate(custom(
        function = "validate_key_size",
        message = "invalid openpgp attribute 'key_length'"
    ))]
    key_length: Option<String>,
    digest_algorithm: OpenPGPDigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid openpgp attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid openpgp attribute 'expire_at'"
    ))]
    expire_at: String,
    passphrase: Option<String>,
}

impl PgpKeyGenerationParameter {
    pub fn get_user_id(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

fn validate_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !PGP_VALID_KEY_SIZE.contains(&key_size) {
        return Err(ValidationError::new(
            "invalid key size, possible values are 2048/3072/4096",
        ));
    }
    Ok(())
}

pub struct OpenPGPPlugin {
    name: String,
    secret_key: Option<SignedSecretKey>,
    public_key: Option<SignedPublicKey>,
    identity: String,
    attributes: HashMap<String, String>,
}

impl OpenPGPPlugin {
    pub fn attributes_validate(
        attr: &HashMap<String, String>,
    ) -> Result<PgpKeyGenerationParameter> {
        let parameter: PgpKeyGenerationParameter =
            serde_json::from_str(serde_json::to_string(&attr)?.as_str())?;
        match parameter.validate() {
            Ok(_) => Ok(parameter),
            Err(e) => Err(Error::ParameterError(format!("{:?}", e))),
        }
    }
}

impl SignPlugins for OpenPGPPlugin {
    fn new(db: SecDataKey, _timestamp_key: Option<SecDataKey>) -> Result<Self> {
        let mut secret_key = None;
        let mut public_key = None;
        if !db.private_key.unsecure().is_empty() {
            let private = from_utf8(db.private_key.unsecure())
                .map_err(|e| Error::KeyParseError(e.to_string()))?;
            let (value, _) = SignedSecretKey::from_string(private)
                .map_err(|e| Error::KeyParseError(e.to_string()))?;
            secret_key = Some(value);
        }

        if !db.public_key.unsecure().is_empty() {
            let public = from_utf8(db.public_key.unsecure())
                .map_err(|e| Error::KeyParseError(e.to_string()))?;
            let (value, _) = SignedPublicKey::from_string(public)
                .map_err(|e| Error::KeyParseError(e.to_string()))?;
            public_key = Some(value);
        }
        Ok(Self {
            name: db.name.clone(),
            secret_key,
            public_key,
            identity: db.identity.clone(),
            attributes: db.attributes,
        })
    }

    fn validate_and_update(key: &mut DataKey) -> Result<()>
    where
        Self: Sized,
    {
        let _ = attributes_validate::<PgpKeyImportParameter>(&key.attributes)?;
        //validate keys
        let private =
            from_utf8(&key.private_key).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (secret_key, _) = SignedSecretKey::from_string(private)
            .map_err(|e| Error::KeyParseError(e.to_string()))?;
        let public = from_utf8(&key.public_key).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (public_key, _) = SignedPublicKey::from_string(public)
            .map_err(|e| Error::KeyParseError(e.to_string()))?;
        //update key attributes
        key.fingerprint = encode_u8_to_hex_string(&secret_key.fingerprint());
        //NOTE: currently we can not get expire at from openpgp key
        match public_key.expires_at() {
            None => {}
            Some(time) => key.expire_at = time,
        }
        Ok(())
    }

    fn parse_attributes(
        _private_key: Option<Vec<u8>>,
        _public_key: Option<Vec<u8>>,
        _certificate: Option<Vec<u8>>,
    ) -> HashMap<String, String> {
        todo!()
    }

    fn generate_keys(
        &self,
        _key_type: &EntityKeyType,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<PgpKeyGenerationParameter>(&self.attributes)?;
        let mut key_params = SecretKeyParamsBuilder::default();
        let create_at = parameter.create_at.parse()?;
        let expire: DateTime<Utc> = parameter.expire_at.parse()?;
        let duration: core::time::Duration = (expire - Utc::now()).to_std()?;
        key_params
            .key_type(
                parameter
                    .key_type
                    .get_real_key_type(parameter.key_length.clone()),
            )
            .can_create_certificates(false)
            .can_sign(true)
            .primary_user_id(parameter.get_user_id())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
            .preferred_hash_algorithms(smallvec![parameter.digest_algorithm.get_real_algorithm()])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB,])
            .created_at(create_at)
            .expiration(Some(duration));
        let secret_key_params = key_params.build()?;
        let secret_key = secret_key_params.generate()?;
        let passwd_fn = || match parameter.passphrase {
            None => String::new(),
            Some(password) => password,
        };
        let signed_secret_key = secret_key.sign(passwd_fn.clone())?;
        let public_key = signed_secret_key.public_key();
        let signed_public_key = public_key.sign(&signed_secret_key, passwd_fn)?;
        Ok(DataKeyContent {
            private_key: signed_secret_key.to_armored_bytes(None)?,
            public_key: signed_public_key.to_armored_bytes(None)?,
            certificate: vec![],
            fingerprint: encode_u8_to_hex_string(&signed_secret_key.fingerprint()),
            serial_number: Some(encode_u8_to_hex_string(&signed_secret_key.fingerprint())),
        })
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let mut digest = HashAlgorithm::SHA2_256;
        if let Some(digest_str) = self.attributes.get("digest_algorithm") {
            digest = OpenPGPDigestAlgorithm::from_str(digest_str)?.get_real_algorithm();
        }
        let passwd_fn = || {
            return match self.attributes.get("passphrase") {
                None => String::new(),
                Some(password) => password.to_string(),
            };
        };
        let now = Utc::now();
        let secret_key_id = self.secret_key.clone().unwrap().key_id();
        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: self.public_key.clone().unwrap().primary_key.algorithm(),
            hash_alg: digest,
            issuer: Some(secret_key_id.clone()),
            created: Some(now),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(now)),
                Subpacket::regular(SubpacketData::Issuer(secret_key_id)),
            ],
        };
        let read_cursor = Cursor::new(content);
        let signature_packet = sig_cfg
            .sign(&self.secret_key.clone().unwrap(), passwd_fn, read_cursor)
            .map_err(|e| Error::SignError(self.identity.clone(), e.to_string()))?;

        //detached signature
        if let Some(detached) = options.get(options::DETACHED) {
            if detached == "true" {
                let standard_signature = StandaloneSignature::new(signature_packet);
                return Ok(standard_signature.to_armored_bytes(None)?);
            }
        }
        let mut signature_bytes = Vec::with_capacity(1024);
        let mut cursor = Cursor::new(&mut signature_bytes);
        write_packet(&mut cursor, &signature_packet)
            .map_err(|e| Error::SignError(self.identity.clone(), e.to_string()))?;
        Ok(signature_bytes)
    }

    fn generate_crl_content(
        &self,
        _revoked_keys: Vec<RevokedKey>,
        _last_update: DateTime<Utc>,
        _next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::domain::datakey::entity::KeyType;
    use crate::domain::datakey::entity::{KeyState, Visibility};
    use crate::domain::encryption_engine::EncryptionEngine;
    use crate::infra::encryption::dummy_engine::DummyEngine;
    use crate::util::options::DETACHED;
    use chrono::{Duration, Utc};
    use rand::Rng;
    use secstr::SecVec;

    fn get_encryption_engine() -> Box<dyn EncryptionEngine> {
        Box::new(DummyEngine::default())
    }

    fn get_default_parameter() -> HashMap<String, String> {
        HashMap::from([
            ("name".to_string(), "fake_name".to_string()),
            ("email".to_string(), "fake_email@email.com".to_string()),
            ("key_type".to_string(), "rsa".to_string()),
            ("key_length".to_string(), "2048".to_string()),
            ("digest_algorithm".to_string(), "sha2_256".to_string()),
            ("create_at".to_string(), Utc::now().to_string()),
            (
                "expire_at".to_string(),
                (Utc::now() + Duration::days(365)).to_string(),
            ),
            ("passphrase".to_string(), "123456".to_string()),
        ])
    }

    fn get_default_datakey(
        name: Option<String>,
        parameter: Option<HashMap<String, String>>,
    ) -> DataKey {
        let now = Utc::now();
        let mut datakey = DataKey {
            id: 0,
            name: "fake".to_string(),
            visibility: Visibility::Public,
            description: "fake description".to_string(),
            user: 1,
            attributes: get_default_parameter(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: now,
            expire_at: now,
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        if let Some(name) = name {
            datakey.name = name;
        }
        if let Some(parameter) = parameter {
            datakey.attributes = parameter;
        }
        datakey
    }

    #[test]
    fn test_key_type_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_type".to_string(), "invalid".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect_err("invalid key type");
        parameter.insert("key_type".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key type");
        for key_type in all::<OpenPGPKeyType>().collect::<Vec<_>>() {
            parameter.insert("key_type".to_string(), key_type.to_string());
            attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect("valid key type");
        }
    }

    #[test]
    fn test_key_size_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_length".to_string(), "1024".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid key length");
        parameter.insert("key_length".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key length");
        for key_length in PGP_VALID_KEY_SIZE {
            parameter.insert("key_length".to_string(), key_length.to_string());
            attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect("valid key length");
        }
    }

    #[test]
    fn test_digest_algorithm_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("digest_algorithm".to_string(), "1234".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid digest algorithm");
        parameter.insert("digest_algorithm".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty digest algorithm");
        for key_length in all::<OpenPGPDigestAlgorithm>().collect::<Vec<_>>() {
            parameter.insert("digest_algorithm".to_string(), key_length.to_string());
            attributes_validate::<PgpKeyGenerationParameter>(&parameter)
                .expect("valid digest algorithm");
        }
    }

    #[test]
    fn test_create_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("create_at".to_string(), "1234".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid create at");
        parameter.insert("create_at".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty create at");
        parameter.insert("create_at".to_string(), Utc::now().to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect("valid create at");
    }

    #[test]
    fn test_expire_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("expire_at".to_string(), "1234".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid expire at");
        parameter.insert("expire_at".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty expire at");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() - Duration::days(1)).to_string(),
        );
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("expire at expired");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() + Duration::minutes(1)).to_string(),
        );
        attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect("valid expire at");
    }

    #[test]
    fn test_email_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("email".to_string(), "fake".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect("invalid email should work");
        parameter.insert("email".to_string(), "".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter)
            .expect_err("invalid empty email");
        parameter.insert("email".to_string(), "tommylikehu@gmail.com".to_string());
        attributes_validate::<PgpKeyGenerationParameter>(&parameter).expect("valid email");
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_digest_hash() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let algorithms = all::<OpenPGPDigestAlgorithm>().collect::<Vec<_>>();
        //choose 3 random digest algorithm
        for _ in [1, 2, 3] {
            let num = rand::thread_rng().gen_range(0..algorithms.len());
            parameter.insert("digest_algorithm".to_string(), algorithms[num].to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone())),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin =
                OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
            plugin
                .generate_keys(&KeyType::OpenPGP, &HashMap::new())
                .expect(
                    format!("generate key with digest {} successfully", algorithms[num]).as_str(),
                );
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_length() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        for key_size in PGP_VALID_KEY_SIZE {
            parameter.insert("key_size".to_string(), key_size.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone())),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin =
                OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
            plugin
                .generate_keys(&KeyType::OpenPGP, &HashMap::new())
                .expect(format!("generate key with key size {} successfully", key_size).as_str());
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_key_type() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        for key_type in all::<OpenPGPKeyType>().collect::<Vec<_>>() {
            parameter.insert("key_type".to_string(), key_type.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone())),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin =
                OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
            plugin
                .generate_keys(&KeyType::OpenPGP, &HashMap::new())
                .expect(format!("generate key with key type {} successfully", key_type).as_str());
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_without_passphrase() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone())),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin =
            OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
        plugin
            .generate_keys(&KeyType::OpenPGP, &HashMap::new())
            .expect(format!("generate key with no passphrase successfully").as_str());
        parameter.insert("passphrase".to_string(), "".to_string());
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone())),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin =
            OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
        plugin
            .generate_keys(&KeyType::OpenPGP, &HashMap::new())
            .expect(format!("generate key with passphrase successfully").as_str());
    }

    #[test]
    fn test_validate_and_update() {
        let public_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGRsiQsBDADKgFlRCXUEkgiV76THsg4OIgtL2ikjE9+N93jGOpXu6nR6Bg6D
/Yjw8LehLpnGlAhwXLlNuG42i/KR7Hb3i75mH8PtOeE7Z/64SEz78/kO+Z5+kJFl
zh3VC4MSqWbKFynTi+exR7hxJjGBanBzHjq67Jy7rtIKi9rgMARL2bD6mOZFm5CA
tyyU3Qzte/KwN3MaMqHjFcu/Hk1pFID1UQ5Lde47DmoCTWBgKoAFnTgXcn35+Ofw
mS9zo4+cN8hFgLsYo5CZD32lGuXFYInY85+wpLDT7SjwZkvCyc45Mlf1CUhCHWKm
VOZy96sfGJ02w1zNW4nGKAG7F2apN+tb6IcK3v6PypDTfq3ApEZ7WgzHvorl0mOe
u/C5vcvWNg7ii6LqJxbwBRxHdBL5bm53eOPbOhRXWFi349lscnNuxULxYDuT6Czr
2oRI0+aUpU5QRHlhpYamYjyQa2i40kUPOZkxbBvwWY1qu9OvJE3OeUCDC0htTl8A
5or9UaakwWCgsM0AEQEAAbQiaHVzaGVuZyAoMTIzKSA8aHVzaGVuZ0BodWF3ZWku
Y29tPokB1AQTAQoAPhYhBGB4DoA1CAGjlbGwgwKltfuHzQWOBQJkbIkLAhsDBQkA
D9IABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEAKltfuHzQWOw8EMAISYNLaH
w0yVGh+3VPyKg73ePYV/Ms7G83zAX8fDHC41E2I5zraN6N7Q0QAh53RKSXWu+7GS
PIXKOTRtqkXPpRPA5hEnMAB3a/nBmx6npgUmalSiFr7G63d0zcIwDseLNWBTI5MO
rdDGXznX506xNYJYjYWkRB8kNvs8agYavwO2D47bwjOmJbZ/AK24//enHvGb6Rfh
fuCptburbPY1lON93PzrdSzFcVdF6BnLXTRXqaAzPFG/zBIusMd8xMX8n/Cj5CL3
lcsR17MTni7aywPKPljWFLM/jPLl5LWkSQyQqd/iOipTqX4cUgQkPdtcR/5wrQMN
tHMpstFn/Ntj2iUWaJUgptWhAzROOVKRlbvPIpSwEZJQ1xoWWdMS0lCRlRp1Yf1r
AG0YQxffrmfhLtZcHCByUGLzjON5Qg5D1BXaNfqo9n1ZzoVSPuFYamXBIPRkYqfl
Q8rJlaXFZEkEAZYoz953QkhYv4MsbFN8ZvXFQyc3WPm6RYjdcY9AGaelhA==
=qpU4
-----END PGP PUBLIC KEY BLOCK-----";
        let private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----

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
j0AZp6WE
=eDZk
-----END PGP PRIVATE KEY BLOCK-----";
        let mut datakey = get_default_datakey(None, None);
        datakey.public_key = public_key.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        OpenPGPPlugin::validate_and_update(&mut datakey).expect("validate and update should work");
        assert_eq!(
            "60780E80350801A395B1B08302A5B5FB87CD058E",
            datakey.fingerprint
        );
    }

    #[tokio::test]
    async fn test_sign_with_armored_text() {
        let content = "hello world".as_bytes();
        let mut parameter = get_default_parameter();
        parameter.insert(DETACHED.to_string(), "true".to_string());
        let dummy_engine = get_encryption_engine();
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone())),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin =
            OpenPGPPlugin::new(sec_datakey, None).expect("create openpgp plugin successfully");
        let keys = plugin
            .generate_keys(&KeyType::OpenPGP, &HashMap::new())
            .expect(format!("generate key successfully").as_str());
        let sec_keys = SecDataKey {
            name: "".to_string(),
            private_key: SecVec::new(keys.private_key.clone()),
            public_key: SecVec::new(keys.public_key.clone()),
            certificate: SecVec::new(keys.certificate.clone()),
            identity: "".to_string(),
            attributes: Default::default(),
            parent: None,
        };
        let instance =
            OpenPGPPlugin::new(sec_keys, None).expect("create openpgp instance successfully");
        let signature = instance
            .sign(content.to_vec(), parameter)
            .expect("sign successfully");
        let signature_text = from_utf8(&signature).expect("signature bytes to string should work");
        assert_eq!(
            true,
            signature_text.contains("-----BEGIN PGP SIGNATURE-----")
        );
        assert_eq!(true, signature_text.contains("-----END PGP SIGNATURE-----"));
        let (standalone, _) =
            StandaloneSignature::from_string(signature_text).expect("parse signature successfully");
        let public = from_utf8(&keys.public_key).expect("parse public key should work");
        let (public_key, _) =
            SignedPublicKey::from_string(public).expect("parse signed public key should work");
        standalone
            .verify(&public_key, content)
            .expect("signature matches");
    }
}
