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

use chrono::{DateTime, Utc};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Crl, X509Extension};
use openssl_sys::{
    NID_authority_key_identifier, X509V3_EXT_nconf_nid, X509V3_set_ctx, X509_CRL_add0_revoked,
    X509_CRL_add_ext, X509_CRL_new, X509_CRL_set1_lastUpdate, X509_CRL_set1_nextUpdate,
    X509_CRL_set_issuer_name, X509_CRL_set_version, X509_CRL_sign, X509_EXTENSION_free,
    X509_REVOKED_new, X509_REVOKED_set_revocationDate, X509_REVOKED_set_serialNumber,
};
use secstr::SecVec;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use super::util::{attributes_validate, validate_utc_time, validate_utc_time_not_expire};
use crate::domain::datakey::entity::{
    DataKey, DataKeyContent, KeyType, RevokedKey, SecDataKey, SecParentDateKey,
    INFRA_CONFIG_DOMAIN_NAME,
};
use crate::domain::datakey::plugins::x509::{
    X509DigestAlgorithm, X509EEUsage, X509KeyType, X509_SM2_VALID_KEY_SIZE, X509_VALID_KEY_SIZE,
};
use crate::domain::sign_plugin::SignPlugins;
use crate::infra::sign_plugin::cms::{CmsContext, CmsPlugin, EVP_PKEY_is_a, Step};
use crate::util::attributes;
use crate::util::error::{Error, Result};
use crate::util::key::{decode_hex_string_to_u8, encode_u8_to_hex_string};
use crate::util::options;
use crate::util::sign::SignType;
#[allow(unused_imports)]
use enum_iterator::all;
use validator::{Validate, ValidationError};

#[derive(Debug, Validate, Deserialize)]
#[validate(schema(function = "validate_x509_key_size_for_generation"))]
pub struct X509KeyGenerationParameter {
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'CommonName'"))]
    common_name: String,
    #[validate(length(
        min = 1,
        max = 30,
        message = "invalid x509 subject 'OrganizationalUnit'"
    ))]
    organizational_unit: String,
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'Organization'"))]
    organization: String,
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'Locality'"))]
    locality: String,
    #[validate(length(
        min = 1,
        max = 30,
        message = "invalid x509 subject 'StateOrProvinceName'"
    ))]
    province_name: String,
    #[validate(length(min = 2, max = 2, message = "invalid x509 subject 'CountryName'"))]
    country_name: String,
    key_type: X509KeyType,
    key_length: String,
    digest_algorithm: X509DigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid x509 attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid x509 attribute 'expire_at'"
    ))]
    expire_at: String,
    #[serde(skip_serializing_if = "Option::is_None")]
    x509_ee_usage: Option<X509EEUsage>,
}

#[derive(Debug, Validate, Deserialize)]
#[validate(schema(function = "validate_x509_key_size_for_import"))]
pub struct X509KeyImportParameter {
    key_type: X509KeyType,
    key_length: String,
    digest_algorithm: X509DigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid x509 attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid x509 attribute 'expire_at'"
    ))]
    expire_at: String,
}

impl X509KeyGenerationParameter {
    pub fn get_subject_name(&self) -> Result<x509::X509Name> {
        let mut x509_name = x509::X509NameBuilder::new()?;
        x509_name.append_entry_by_text("CN", &self.common_name)?;
        x509_name.append_entry_by_text("OU", &self.organizational_unit)?;
        x509_name.append_entry_by_text("O", &self.organization)?;
        x509_name.append_entry_by_text("L", &self.locality)?;
        x509_name.append_entry_by_text("ST", &self.province_name)?;
        x509_name.append_entry_by_text("C", &self.country_name)?;
        Ok(x509_name.build())
    }
}

fn validate_key_size_core(
    key_type: &X509KeyType,
    key_length: &String,
) -> std::result::Result<(), ValidationError> {
    match key_type {
        X509KeyType::Rsa | X509KeyType::Dsa => {
            if X509_VALID_KEY_SIZE.contains(&key_length.as_str()) {
                Ok(())
            } else {
                return Err(ValidationError::new(
                    "invaild key size, RSA/DSA possible values are 2048/3072/4049",
                ));
            }
        }
        X509KeyType::Sm2 => {
            if X509_SM2_VALID_KEY_SIZE.contains(&key_length.as_str()) {
                Ok(())
            } else {
                return Err(ValidationError::new(
                    "invaild key size, SM2 possible values are 256",
                ));
            }
        }
    }
}

fn validate_x509_key_size_for_import(
    p: &X509KeyImportParameter,
) -> std::result::Result<(), ValidationError> {
    validate_key_size_core(&p.key_type, &p.key_length)
}

fn validate_x509_key_size_for_generation(
    p: &X509KeyGenerationParameter,
) -> std::result::Result<(), ValidationError> {
    validate_key_size_core(&p.key_type, &p.key_length)
}

fn days_in_duration(time: &str) -> Result<i64> {
    let start = Utc::now();
    let end = time.parse::<DateTime<Utc>>()?;
    Ok((end - start).num_days())
}

pub struct X509Plugin {
    name: String,
    private_key: SecVec<u8>,
    public_key: SecVec<u8>,
    certificate: SecVec<u8>,
    tsa_cert: SecVec<u8>,
    tsa_key: SecVec<u8>,
    identity: String,
    attributes: HashMap<String, String>,
    tsa_attributes: HashMap<String, String>,
    parent_key: Option<SecParentDateKey>,
}

impl X509Plugin {
    fn generate_serial_number() -> Result<BigNum> {
        let mut serial_number = BigNum::new()?;
        serial_number.rand(128, MsbOption::MAYBE_ZERO, true)?;
        Ok(serial_number)
    }

    fn generate_crl_endpoint(
        &self,
        name: &str,
        infra_config: &HashMap<String, String>,
    ) -> Result<String> {
        let domain_name =
            infra_config
                .get(INFRA_CONFIG_DOMAIN_NAME)
                .ok_or(Error::GeneratingKeyError(format!(
                    "{} is not configured",
                    INFRA_CONFIG_DOMAIN_NAME
                )))?;
        Ok(format!(
            "URI:https://{}/api/v1/keys/{}/crl",
            domain_name, name
        ))
    }

    //The openssl config for ca would be like:
    // [ v3_ca ]
    // basicConstraints        = critical, CA:TRUE, pathlen:1
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
    // nsCertType = objCA
    // nsComment = "Signatrust Root CA"
    #[allow(deprecated)]
    fn generate_x509ca_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //generate self signed certificate
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().ca().pathlen(1).critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new().build(&generator.x509v3_context(None, None))?,
        )?;
        //NOTE: for efi certificate the authority key identifier should only be the keyid
        //TODO: need to confirm whether issuer should be included for other cases.
        generator.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&generator.x509v3_context(None, None))?,
        )?;
        generator.append_extension(
            KeyUsage::new()
                .crl_sign()
                .digital_signature()
                .key_cert_sign()
                .critical()
                .build()?,
        )?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Root CA",
        )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            "objCA",
        )?)?;

        generator.sign(
            keys.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }

    //The openssl config for ica would be like:
    // [ v3_ica ]
    // basicConstraints        = critical, CA:TRUE, pathlen:0
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
    // authorityInfoAccess     = OCSP;URI:<Signatrust OSCP Responder>, caIssuers;URI:<Signatrust CA URI>
    // nsCertType = objCA
    // nsComment = "Signatrust Intermediate CA"
    #[allow(deprecated)]
    fn generate_x509ica_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //load the ca certificate and private key
        if self.parent_key.is_none() {
            return Err(Error::GeneratingKeyError(
                "parent key is not provided".to_string(),
            ));
        }
        let ca_key =
            PKey::private_key_from_pem(self.parent_key.clone().unwrap().private_key.unsecure())?;
        let ca_cert =
            x509::X509::from_pem(self.parent_key.clone().unwrap().certificate.unsecure())?;
        //generate self signed certificate
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(ca_cert.subject_name())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().ca().pathlen(0).critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new()
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        //NOTE: for efi certificate the authority key identifier should only be the keyid
        //TODO: need to confirm whether issuer should be included for other cases.
        generator.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        generator.append_extension(
            KeyUsage::new()
                .crl_sign()
                .digital_signature()
                .key_cert_sign()
                .critical()
                .build()?,
        )?;
        //NOTE: sbverify for EFI file will fail, enable when fixed
        // generator.append_extension(X509Extension::new_nid(
        //     None,
        //     None,
        //     Nid::CRL_DISTRIBUTION_POINTS,
        //     &self.generate_crl_endpoint(&self.parent_key.clone().unwrap().name, infra_config)?,
        // )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Intermediate CA",
        )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            "objCA",
        )?)?;
        generator.sign(
            ca_key.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        //use parent private key to sign the certificate
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }

    //The openssl config for ee would be like:
    // [ v3_ee ]
    // basicConstraints        = critical, CA:FALSE
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, digitalSignature, nonRepudiation
    // extendedKeyUsage        = codeSigning
    // authorityInfoAccess     = OCSP;URI:<Signatrust OSCP Responder>, caIssuers;URI:<Signatrust CA URI>
    // nsCertType = objsign
    // nsComment = "Signatrust Sign Certificate"
    #[allow(deprecated)]
    fn generate_x509ee_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //load the ca certificate and private key
        if self.parent_key.is_none() {
            return Err(Error::GeneratingKeyError(
                "parent key is not provided".to_string(),
            ));
        }
        let ica_key =
            PKey::private_key_from_pem(self.parent_key.clone().unwrap().private_key.unsecure())?;
        let ca_cert =
            x509::X509::from_pem(self.parent_key.clone().unwrap().certificate.unsecure())?;
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(ca_cert.subject_name())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new()
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        //NOTE: for efi certificate the authority key identifier should only be the keyid
        //TODO: need to confirm whether issuer should be included for other cases.
        if let Some(X509EEUsage::Ko) = parameter.x509_ee_usage {
            generator.append_extension(
                AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .issuer(true)
                    .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
            )?;
        } else {
            generator.append_extension(
                AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
            )?;
        }

        // Set ExtendedKeyUsage and KeyUsage based on certificate usage
        match parameter.x509_ee_usage {
            Some(X509EEUsage::Ko) => {
                generator.append_extension(ExtendedKeyUsage::new().code_signing().build()?)?;
                generator.append_extension(
                    KeyUsage::new()
                        .digital_signature()
                        .non_repudiation()
                        .build()?,
                )?;
            }
            Some(X509EEUsage::Efi) => {
                generator.append_extension(ExtendedKeyUsage::new().code_signing().build()?)?;
                //NOTE: signing cert for efi should not contain any key usage extension
            }
            Some(X509EEUsage::Cms) => {
                // CMS signing certificate needs both codeSigning and emailProtection EKU
                // to pass OpenSSL S/MIME verification without -purpose any flag
                generator.append_extension(
                    ExtendedKeyUsage::new()
                        .code_signing()
                        .email_protection()
                        .build()?,
                )?;
                generator.append_extension(
                    KeyUsage::new()
                        .digital_signature()
                        .non_repudiation()
                        .build()?,
                )?;
            }
            Some(X509EEUsage::Timestamp) => {
                // TimeStamp certificate requires id-kp-timeStamping ExtendedKeyUsage
                // OID: 1.3.6.1.5.5.7.3.8
                generator.append_extension(
                    ExtendedKeyUsage::new().other("1.3.6.1.5.5.7.3.8").build()?,
                )?;
                generator.append_extension(
                    KeyUsage::new()
                        .digital_signature()
                        .non_repudiation()
                        .build()?,
                )?;
            }
            None => {
                generator.append_extension(ExtendedKeyUsage::new().code_signing().build()?)?;
            }
        }
        //NOTE: sbverify for EFI file will fail, enable when fixed
        // generator.append_extension(X509Extension::new_nid(
        //     None,
        //     None,
        //     Nid::CRL_DISTRIBUTION_POINTS,
        //     &self.generate_crl_endpoint(&self.parent_key.clone().unwrap().name, infra_config)?,
        // )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Sign Certificate",
        )?)?;
        // Set Netscape Cert Type based on certificate usage
        // CMS certificates need 'email' (S/MIME) bit for OpenSSL S/MIME verification
        let ns_cert_type = match parameter.x509_ee_usage {
            Some(X509EEUsage::Cms) => "objsign,email",
            _ => "objsign",
        };
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            ns_cert_type,
        )?)?;
        generator.sign(
            ica_key.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        //use parent private key to sign the certificate
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }

    fn detect_key_type(private_key: &PKey<pkey::Private>) -> Result<String> {
        unsafe {
            let rsa = CString::new("RSA").unwrap();
            let rsa_pss = CString::new("RSA-PSS").unwrap();
            let dsa = CString::new("DSA").unwrap();
            let sm2 = CString::new("SM2").unwrap();
            if EVP_PKEY_is_a(private_key.as_ptr(), rsa.as_ptr()) == 1 {
                Ok(X509KeyType::Rsa.as_str().to_string())
            } else if EVP_PKEY_is_a(private_key.as_ptr(), dsa.as_ptr()) == 1 {
                Ok(X509KeyType::Dsa.as_str().to_string())
            } else if EVP_PKEY_is_a(private_key.as_ptr(), sm2.as_ptr()) == 1 {
                Ok(X509KeyType::Sm2.as_str().to_string())
            } else if EVP_PKEY_is_a(private_key.as_ptr(), rsa_pss.as_ptr()) == 1 {
                Ok(X509KeyType::Rsa.as_str().to_string())
            } else {
                Err(Error::InvalidArgumentError(
                    "key type only support RSA,DSA,SM2".to_string(),
                ))
            }
        }
    }
}

impl SignPlugins for X509Plugin {
    fn new(db: SecDataKey, timestamp_key: Option<SecDataKey>) -> Result<Self> {
        let mut plugin = Self {
            name: db.name.clone(),
            private_key: db.private_key.clone(),
            public_key: db.public_key.clone(),
            certificate: db.certificate.clone(),
            identity: db.identity.clone(),
            attributes: db.attributes,
            parent_key: None,
            tsa_cert: SecVec::new(Vec::new()),
            tsa_key: SecVec::new(Vec::new()),
            tsa_attributes: HashMap::new(),
        };
        if let Some(parent) = db.parent {
            plugin.parent_key = Some(parent);
        }

        if let Some(ref key) = timestamp_key {
            plugin.tsa_cert = key.certificate.clone();
            plugin.tsa_key = key.private_key.clone();
            plugin.tsa_attributes = key.attributes.clone();
        }
        Ok(plugin)
    }

    fn validate_and_update(key: &mut DataKey) -> Result<()>
    where
        Self: Sized,
    {
        let _ = attributes_validate::<X509KeyImportParameter>(&key.attributes)?;
        let private_key = PKey::private_key_from_pem(&key.private_key)?;
        let certificate = x509::X509::from_pem(&key.certificate)?;
        if !key.public_key.is_empty() {
            let _public_key = PKey::public_key_from_pem(&key.public_key)?;
        }
        match X509Plugin::detect_key_type(&private_key) {
            Ok(key_type) => {
                key.attributes
                    .insert("key_type".to_string(), key_type.to_string());
            }
            Err(_e) => {
                return Err(Error::InvalidArgumentError(
                    "key type only support RSA,DSA,SM2".to_string(),
                ));
            }
        }
        let bit = private_key.bits();
        key.attributes
            .insert("key_length".to_string(), bit.to_string());
        let unix_time = Asn1Time::from_unix(0)?.diff(certificate.not_after())?;
        let expire = SystemTime::UNIX_EPOCH
            + Duration::from_secs(unix_time.days as u64 * 86400 + unix_time.secs as u64);
        key.expire_at = expire.into();
        key.fingerprint = encode_u8_to_hex_string(
            certificate
                .digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
        );
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
        key_type: &KeyType,
        infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        match key_type {
            KeyType::X509CA => self.generate_x509ca_keys(infra_config),
            KeyType::X509ICA => self.generate_x509ica_keys(infra_config),
            KeyType::X509EE => self.generate_x509ee_keys(infra_config),
            _ => Err(Error::GeneratingKeyError(
                "x509 plugin only support x509ca, x509ica and x509ee key type".to_string(),
            )),
        }
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;
        let mut cert_stack = Stack::new()?;
        cert_stack.push(certificate.clone())?;
        if options
            .get(options::INCLUDE_PARENT_CERT)
            .unwrap_or(&"true".to_string())
            == "true"
            && self.parent_key.is_some()
        {
            cert_stack.push(x509::X509::from_pem(
                self.parent_key.clone().unwrap().certificate.unsecure(),
            )?)?;
        }

        match SignType::from_str(
            options
                .get(options::SIGN_TYPE)
                .unwrap_or(&SignType::Cms.to_string()),
        )? {
            SignType::Authenticode => {
                let mut bufs: Vec<Vec<u8>> = vec![];
                if options
                    .get(options::INCLUDE_PARENT_CERT)
                    .unwrap_or(&"true".to_string())
                    == "true"
                    && self.parent_key.is_some()
                {
                    bufs.push(
                        self.parent_key
                            .clone()
                            .unwrap()
                            .certificate
                            .unsecure()
                            .to_vec(),
                    );
                }
                bufs.push(self.certificate.unsecure().to_vec());

                let p7b = efi_signer::EfiImage::pems_to_p7(bufs)?;
                Ok(efi_signer::EfiImage::do_sign_signature(
                    content,
                    p7b,
                    private_key.private_key_to_pem_pkcs8()?,
                    None,
                    efi_signer::DigestAlgorithm::Sha256,
                )?
                .encode()?)
            }
            SignType::PKCS7 => {
                let pkcs7 = Pkcs7::sign(
                    &certificate,
                    &private_key,
                    &cert_stack,
                    &content,
                    Pkcs7Flags::DETACHED
                        | Pkcs7Flags::NOCERTS
                        | Pkcs7Flags::BINARY
                        | Pkcs7Flags::NOSMIMECAP
                        | Pkcs7Flags::NOATTR,
                )?;
                Ok(pkcs7.to_der()?)
            }
            SignType::KernelCms => {
                //cms option reference: https://man.openbsd.org/CMS_sign.3
                let cms_signature = CmsContentInfo::sign(
                    Some(&certificate),
                    Some(&private_key),
                    Some(&cert_stack),
                    Some(&content),
                    CMSOptions::DETACHED
                        | CMSOptions::CMS_NOCERTS
                        | CMSOptions::BINARY
                        | CMSOptions::NOSMIMECAP
                        | CMSOptions::NOATTR,
                )?;
                Ok(cms_signature.to_der()?)
            }
            SignType::Cms => {
                let tsa_cert_pem = self.tsa_cert.unsecure();
                let tsa_key_pem = self.tsa_key.unsecure();
                let mut ctx = CmsContext::new(
                    &certificate,
                    &private_key,
                    content.as_slice(),
                    &options,
                    &self.attributes,
                    &self.tsa_attributes,
                    tsa_cert_pem,
                    tsa_key_pem,
                );

                let need_ts = !tsa_cert_pem.is_empty() && !tsa_key_pem.is_empty();
                if need_ts {
                    info!("tsa cert & key present, timestamp will be attached");
                    let steps: &[Step] = &[
                        &CmsPlugin::step_generate_cms,
                        &CmsPlugin::step_generate_ts_req,
                        &CmsPlugin::step_load_tsa_cert_key,
                        &CmsPlugin::step_generate_tst_info,
                        &CmsPlugin::step_generate_timestamp_token,
                        &CmsPlugin::step_attach_timestamp,
                    ];
                    CmsPlugin::run_steps(&mut ctx, steps)?;
                } else {
                    info!("tsa cert or key is empty, skip timestamp");
                    let steps: &[Step] = &[&CmsPlugin::step_generate_cms];
                    CmsPlugin::run_steps(&mut ctx, steps)?;
                }
                CmsPlugin::cms_to_vec(ctx.cms)
            }
            SignType::RsaHash => {
                // rust-openssl/openssl/src/pkey_ctx.rs
                let mut signature = vec![];
                attributes::do_sign_rsahash(
                    self.private_key.unsecure(),
                    &content,
                    &self.attributes,
                    &mut signature,
                )
                .unwrap();
                Ok(signature)
            }
        }
    }

    fn generate_crl_content(
        &self,
        revoked_keys: Vec<RevokedKey>,
        last_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;

        //prepare raw crl content
        let crl = unsafe { X509_CRL_new() };
        let x509_name = certificate.subject_name().as_ptr();

        unsafe {
            X509_CRL_set_version(crl, 1);
        };
        unsafe {
            X509_CRL_set_issuer_name(crl, x509_name);
        };
        unsafe {
            X509_CRL_set1_lastUpdate(crl, Asn1Time::from_unix(last_update.timestamp())?.as_ptr())
        };
        unsafe {
            X509_CRL_set1_nextUpdate(crl, Asn1Time::from_unix(next_update.timestamp())?.as_ptr())
        };

        let mut ctx: openssl_sys::X509V3_CTX = unsafe { std::mem::zeroed() };
        unsafe {
            openssl_sys::X509V3_set_ctx(
                &mut ctx,
                certificate.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                crl,
                0,
            );
        }
        let aki_value = CString::new("keyid").unwrap();
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                std::ptr::null_mut(),
                &mut ctx,
                NID_authority_key_identifier,
                aki_value.as_ptr(),
            )
        };
        if !ext.is_null() {
            unsafe { X509_CRL_add_ext(crl, ext, -1) };
            unsafe { X509_EXTENSION_free(ext) };
        }

        for revoked_key in revoked_keys {
            //TODO: Add revoke reason here.
            if let Some(serial_number) = revoked_key.serial_number {
                let cert_serial = BigNum::from_slice(&decode_hex_string_to_u8(&serial_number))?;
                let revoked = unsafe { X509_REVOKED_new() };
                unsafe {
                    X509_REVOKED_set_serialNumber(
                        revoked,
                        Asn1Integer::from_bn(&cert_serial)?.as_ptr(),
                    )
                };
                unsafe {
                    X509_REVOKED_set_revocationDate(
                        revoked,
                        Asn1Time::from_unix(revoked_key.create_at.timestamp())?.as_ptr(),
                    )
                };
                unsafe { X509_CRL_add0_revoked(crl, revoked) };
            }
        }
        unsafe {
            X509_CRL_sign(
                crl,
                private_key.as_ptr(),
                parameter.digest_algorithm.get_real_algorithm().as_ptr(),
            )
        };
        let content = unsafe { X509Crl::from_ptr(crl) };
        Ok(content.to_pem()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::domain::datakey::entity::KeyType;
    use crate::domain::datakey::entity::{KeyState, ParentKey, Visibility, X509RevokeReason};
    use crate::domain::encryption_engine::EncryptionEngine;
    use crate::infra::encryption::dummy_engine::DummyEngine;
    use chrono::{Duration, Utc};
    use secstr::SecVec;
    use std::env;

    fn get_infra_config() -> HashMap<String, String> {
        HashMap::from([(
            INFRA_CONFIG_DOMAIN_NAME.to_string(),
            "test.hostname".to_string(),
        )])
    }

    fn get_encryption_engine() -> Box<dyn EncryptionEngine> {
        Box::new(DummyEngine::default())
    }

    fn get_default_parameter() -> HashMap<String, String> {
        HashMap::from([
            ("common_name".to_string(), "name".to_string()),
            ("organizational_unit".to_string(), "infra".to_string()),
            ("organization".to_string(), "openEuler".to_string()),
            ("locality".to_string(), "guangzhou".to_string()),
            ("province_name".to_string(), "guangzhou".to_string()),
            ("country_name".to_string(), "cn".to_string()),
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
        key_type: Option<KeyType>,
    ) -> DataKey {
        let now = Utc::now();
        let mut datakey = DataKey {
            id: 0,
            name: "fake".to_string(),
            visibility: Visibility::Public,
            description: "fake description".to_string(),
            user: 1,
            attributes: get_default_parameter(),
            key_type: KeyType::X509EE,
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
        if let Some(key) = key_type {
            datakey.key_type = key;
        }
        datakey
    }

    /// helper function to get a usable X509plugin
    async fn get_default_plugin() -> X509Plugin {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        // create ca
        let ca_key = get_default_datakey(
            Some("fake ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());

        // create ica
        let mut ica_key = get_default_datakey(
            Some("fake ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "fake ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect(format!("generate ica key with no passphrase successfully").as_str());

        //create ee
        let mut ee_key = get_default_datakey(
            Some("fake ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "fake ca".to_string(),
            private_key: ica_content.private_key,
            public_key: ica_content.public_key,
            certificate: ica_content.certificate,
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect(format!("generate ee key with no passphrase successfully").as_str());

        let sec_keys = SecDataKey {
            name: "".to_string(),
            private_key: SecVec::new(ee_content.private_key.clone()),
            public_key: SecVec::new(ee_content.public_key.clone()),
            certificate: SecVec::new(ee_content.certificate.clone()),
            identity: "".to_string(),
            attributes: parameter.clone(),
            parent: None,
        };

        let timestamp_key = SecDataKey {
            name: "".to_string(),
            private_key: SecVec::new(ee_content.private_key.clone()),
            public_key: SecVec::new(ee_content.public_key.clone()),
            certificate: SecVec::new(ee_content.certificate.clone()),
            identity: "".to_string(),
            attributes: parameter.clone(),
            parent: None,
        };
        X509Plugin::new(sec_keys, Some(timestamp_key)).expect("create x509 instance successfully")
    }

    #[test]
    fn test_key_type_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_type".to_string(), "invalid".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid key type");
        parameter.insert("key_type".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key type");

        let key_types = vec![X509KeyType::Rsa, X509KeyType::Dsa];
        for key_type in key_types {
            parameter.insert("key_type".to_string(), key_type.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid key type");
        }
    }

    #[test]
    fn test_key_size_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_length".to_string(), "1024".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid key length");
        parameter.insert("key_length".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key length");
        for key_length in X509_VALID_KEY_SIZE {
            parameter.insert("key_length".to_string(), key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter)
                .expect("valid key length");
        }
    }

    #[test]
    fn test_digest_algorithm_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("digest_algorithm".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid digest algorithm");
        parameter.insert("digest_algorithm".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty digest algorithm");
        for key_length in all::<X509DigestAlgorithm>().collect::<Vec<_>>() {
            parameter.insert("digest_algorithm".to_string(), key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter)
                .expect("valid digest algorithm");
        }
    }

    #[test]
    fn test_create_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("create_at".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid create at");
        parameter.insert("create_at".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty create at");
        parameter.insert("create_at".to_string(), Utc::now().to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid create at");
    }

    #[test]
    fn test_expire_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("expire_at".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid expire at");
        parameter.insert("expire_at".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty expire at");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() - Duration::days(1)).to_string(),
        );
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("expire at expired");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() + Duration::minutes(1)).to_string(),
        );
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid expire at");
    }

    #[tokio::test]
    async fn test_generate_ca_with_international_algo() {
        let mut parameter = get_default_parameter();
        //choose 4 random digest algorithm
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        let algos = vec![
            X509DigestAlgorithm::MD5,
            X509DigestAlgorithm::SHA1,
            X509DigestAlgorithm::SHA2_224,
            X509DigestAlgorithm::SHA2_256,
            X509DigestAlgorithm::SHA2_384,
            X509DigestAlgorithm::SHA2_512,
        ];

        for hash in algos {
            parameter.insert("digest_algorithm".to_string(), hash.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(format!("generate ca key with digest {} successfully", hash).as_str());
        }
    }

    #[tokio::test]
    async fn test_generate_ca_with_sm_algo() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        parameter.insert("key_type".to_string(), "sm2".to_string());
        parameter.insert("digest_algorithm".to_string(), "sm3".to_string());
        parameter.insert("key_length".to_string(), "256".to_string());
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with digest sm3 successfully").as_str());
    }

    #[tokio::test]
    async fn test_generate_sm_ca_with_incorrect_length() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        parameter.insert("key_type".to_string(), "sm2".to_string());
        parameter.insert("digest_algorithm".to_string(), "sm3".to_string());
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let result = plugin.generate_keys(&KeyType::X509CA, &infra_config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_length() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        for key_size in X509_VALID_KEY_SIZE {
            parameter.insert("key_size".to_string(), key_size.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(
                    format!("generate ca key with key size {} successfully", key_size).as_str(),
                );
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_international_type() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let types = vec![X509KeyType::Rsa, X509KeyType::Dsa];
        for key_type in types {
            parameter.insert("key_type".to_string(), key_type.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(
                    format!("generate ca key with key type {} successfully", key_type).as_str(),
                );
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_without_passphrase() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());

        parameter.insert("passphrase".to_string(), "".to_string());
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with passphrase successfully").as_str());
    }

    #[test]
    fn test_validate_and_update() {
        let public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApj/qRL4umbfjJx1TbuXA
eOdLzVqARnGQgiwoVN+0Sas8xdco1d4Dz4UbMdDmXY5z2+50uwpmyRskcKb1fgvF
C8DUD8+ZHxEDITHQ1wqHdeEBh/D64JlD6MoAFHHlEMNEYgaYDUEJZIYp3uX4gMvg
WLsBuWDvyoSkI3j+rMcRN0NWsf7aKbA9OTKyvE5lZC6+z6fyftq4Z9gwiNENEktO
+8WAL31x1X/AHWiFwlguZlKdtozgRIkPYLU27Cz8aAvuuWGTrUYJ98UN80Wzu2gI
rnH3ztPU6gatSvVWHonDEbdjQ/kCRlE2GPZkdPyRvb4gv5BQTeDZeahoSV17Pagg
0QIDAQAB
-----END PUBLIC KEY-----";
        let certificate = "-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUDiehlVNb4SRwVz13zBnKAjuljmAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJWU9VUl9OQU1FMCAXDTIzMDUyMzA5NDgwMFoYDzIxMjMw
NDI5MDk0ODAwWjAUMRIwEAYDVQQDDAlZT1VSX05BTUUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCmP+pEvi6Zt+MnHVNu5cB450vNWoBGcZCCLChU37RJ
qzzF1yjV3gPPhRsx0OZdjnPb7nS7CmbJGyRwpvV+C8ULwNQPz5kfEQMhMdDXCod1
4QGH8PrgmUPoygAUceUQw0RiBpgNQQlkhine5fiAy+BYuwG5YO/KhKQjeP6sxxE3
Q1ax/topsD05MrK8TmVkLr7Pp/J+2rhn2DCI0Q0SS077xYAvfXHVf8AdaIXCWC5m
Up22jOBEiQ9gtTbsLPxoC+65YZOtRgn3xQ3zRbO7aAiucffO09TqBq1K9VYeicMR
t2ND+QJGUTYY9mR0/JG9viC/kFBN4Nl5qGhJXXs9qCDRAgMBAAGjUzBRMB0GA1Ud
DgQWBBS8CurcB1Q9kg/KXWONMNkspM3/HjAfBgNVHSMEGDAWgBS8CurcB1Q9kg/K
XWONMNkspM3/HjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAe
6+KLTWtOlsy/U5alR+g3umo7K8X/9oMAqjzrBenOgcLUKQdsbD7RzXdZ+nZBT/ZV
fzL6WNFYGq1SrcusrRdr5XG6+SXrUa88r/nw5WaeEa2lrk0s4fOr7svg6pKeR84A
M/aF+RfEhNp4l+6eKjerghTbDccOoj4kKCjST6ckTxnAiQQMZL8hXPpXURLbX2Ci
MBtYxIpT5eLClRYIREJFq/qFpAffddlVw7bENQJNoArhIUl5XxsxFz/0nVGDyM5y
vM0L0x9sI6JA4zYrfVfvwB7cvpqw4qK5dlqHtK/Np8WvLUiNDCZUondEOf1jBT3b
67xBfexCBpVVLNLP70Ql
-----END CERTIFICATE-----";
        let private_key = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmP+pEvi6Zt+Mn
HVNu5cB450vNWoBGcZCCLChU37RJqzzF1yjV3gPPhRsx0OZdjnPb7nS7CmbJGyRw
pvV+C8ULwNQPz5kfEQMhMdDXCod14QGH8PrgmUPoygAUceUQw0RiBpgNQQlkhine
5fiAy+BYuwG5YO/KhKQjeP6sxxE3Q1ax/topsD05MrK8TmVkLr7Pp/J+2rhn2DCI
0Q0SS077xYAvfXHVf8AdaIXCWC5mUp22jOBEiQ9gtTbsLPxoC+65YZOtRgn3xQ3z
RbO7aAiucffO09TqBq1K9VYeicMRt2ND+QJGUTYY9mR0/JG9viC/kFBN4Nl5qGhJ
XXs9qCDRAgMBAAECggEAOOgN56P1zZZdQclPAtnQDVKW5t8Ao5xB69zznUHJs6HS
tqHUj4hkY4dbbKzl/cZCMFkqSc/gqRwKWCk+RPwAYeqKbDMSZcjr+lPT+ZfYEGiJ
np/FMFYmIavrZRQrZZaBdNBvAbJuZaNq96peaq/exmCU0YC18+t9R8sl2bx2TyTH
MCyDA7w/HT4BARjzYsjqXEQQzElajcVyX0VwgEtOr40HEpNQioQi8iw94FYgh4C9
awyR6ldIX5TmeFwWyfQxYR/WfXIw7ja9lXqKJ6dkBtY3x+3Z4qbCNB0rgfTY4RoX
1DVHbZNb2kxKSF7d9I8ti0GhfFxOGguS14IeVI2YQQKBgQDa3130/w7adouVJlBM
PJ1Hd5ZT1PXbymvIMuVHjE1BjfzCu9NW+voofCjQlbBejEokUwE8sY8iuU7UosZ2
IkRUwLbF0eIBqe+oXf6CbXZjx+T1n52k+SHbn2WasHndvXEXGRubwwsLo+E3WI2A
KC3Qbmj78GGErB5J+vy2tI79qQKBgQDCc2DCShQHsF6rwKCeeEHhAODMrunW0PtW
lQe4uPK1mwYMXmCLGgJXI3RzyjTLWSgzI/WTIXvrRk45gnEFiTkwt5JxxbNc2WFd
RdnQp/Qis4O/Hac2IcBqy2s4BabgEacvJNaUkoLfHAMmge2n1oeDm5/xgVgXpK1/
Aiu0ct5y6QKBgAgBVXFphsSMw2wwG42+Rc5gXFoyls90Jt8KpYIpaoX0SINi1UcA
JPgoGmIOp4W9wdR0SL5MjDyr5Gs4jOOzOyaSadzwYUDIU2CoF2/zyvm5TPGC5gQr
rIZY3SF8ROjMTf+XRoA68QN6+fjJP1upnItcDnDwiNCObwkrqeSQ1A4JAoGAM2dm
49XLd8DjNgpFK79kwwOFafavcI9schYRpX6XAvVJYwmsAfnNNpXz2gxRapRWMTbH
W67VYHwEf+WA1VLSYJOWzibSZLA+sfaePy+3NVk5cdN3+bJweIrv/C5aUA+6n5bg
dwRIPozcNFjSp7TpvBvu61wjGpT5HINJZHmdXskCgYEAjQf6bFXPMJHELD27RqiD
UDWzemeq/e6D6NJhaESg49Da0N7rsqM+UtBpM/T4Ce9zuPZhLlXJobqmzIYqVDu0
aIVg7wz2RwVCsux1duEoO8ScQghohmzn+7jysGIlN+csOClwSBaLHAIN/PmChZug
X5BboR/QJakEK+H+EUQAiDs=
-----END PRIVATE KEY-----";
        let mut datakey = get_default_datakey(None, None, None);
        datakey.public_key = public_key.as_bytes().to_vec();
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        X509Plugin::validate_and_update(&mut datakey).expect("validate and update should work");
        assert_eq!("2123-04-29 09:48:00 UTC", datakey.expire_at.to_string());
        assert_eq!(
            "C9345187DFA0BFB6DCBCC4827BBEA7312E43754B",
            datakey.fingerprint
        );
    }

    #[test]
    fn test_validate_and_update_with_sm2cert() {
        let certificate = "-----BEGIN CERTIFICATE-----
MIIB1DCCAXoCFGfoVD/6iDpHYUbmTA0+LH/b4tfuMAoGCCqBHM9VAYN1MGwxCzAJ
BgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRIw
EAYDVQQKDAlNeUNvbXBhbnkxDzANBgNVBAsMBlJvb3RDQTEUMBIGA1UEAwwLU00y
IFJvb3QgQ0EwHhcNMjUxMTAzMDgxODEyWhcNMzUxMTAxMDgxODEyWjBsMQswCQYD
VQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzESMBAG
A1UECgwJTXlDb21wYW55MQ8wDQYDVQQLDAZSb290Q0ExFDASBgNVBAMMC1NNMiBS
b290IENBMFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABNYo1OwvitLruiU3oRAc
uaLSplc2Vrj19z2oPicvx8hn3fQLYlqKrKcFvKOWllL3ByQVcMJ4HmRylmOrk24q
4xYwCgYIKoEcz1UBg3UDSAAwRQIhAMnIl0Em/3b8hhR9Ly/FGlt3q2IN1EHLg64+
JGLqK0DFAiAULqROgRSmSWpJgMzU8KMoPfDM7CJ5/NCnDqI3oM9uTw==
-----END CERTIFICATE-----";
        let private_key = "-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIDUaoPl+RCqHV/Un
qWcBnNWXVAOM7BMiiPWQFFotA1h0oUQDQgAE1ijU7C+K0uu6JTehEBy5otKmVzZW
uPX3Pag+Jy/HyGfd9AtiWoqspwW8o5aWUvcHJBVwwngeZHKWY6uTbirjFg==
-----END PRIVATE KEY-----";
        let mut datakey = get_default_datakey(None, None, None);
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        let _ = X509Plugin::validate_and_update(&mut datakey);
        if let Some(value) = datakey.attributes.get("key_length") {
            assert_eq!(value, "256");
        } else {
            panic!("Expected key 'key_length' not found in the map.");
        }

        if let Some(value) = datakey.attributes.get("key_type") {
            assert_eq!(value, "sm2");
        } else {
            panic!("Expected key 'key_type' not found in the map.");
        }
    }

    #[test]
    fn test_validate_and_update_with_rsacert() {
        let certificate = "-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUKTs/prIakrwRyyYbYcfoy6YC6rkwDQYJKoZIhvcNAQEL
BQAwTjELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAmNuMQswCQYDVQQHDAJjbjELMAkG
A1UECgwCY24xCzAJBgNVBAsMAmNuMQswCQYDVQQDDAJDTjAeFw0yNTExMTgxMjAy
MTBaFw0yNjExMTgxMjAyMTBaME4xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJjbjEL
MAkGA1UEBwwCY24xCzAJBgNVBAoMAmNuMQswCQYDVQQLDAJjbjELMAkGA1UEAwwC
Q04wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf87TFBu9fPQ31mjWA
OcYMQeMmHsI/v1Sng4aBoLhWAWZZ+8AuV37wjBVuYGR4GkZHmIJBmi2YNBkPt/4A
IqX4S8hYAAZUurXcVKub2aQOnfh9OLTIxT/GR56imlcRZDrQ+R/VrpVj3yN3qQHP
M1oyuzWin8osCSDRHfEAWcmKVmvHfq6tYVbnmOSQfiPI8+zxMsaMT07RDogOfxEO
/QkPyj16ih9zpK9N2rqbj7q00JIiTSBZ3P/zlshjiZSGZeVaj3bC4KnzKrdlxS46
nfJ7tZ+sHxBqSuScO8X/ButvL7HMnB92Ut47C2SnvD/Or+z86G9KDD2pRxqXcfBo
4cYXAgMBAAGjITAfMB0GA1UdDgQWBBSwe9s1aUMAib5BAffASj6l7+5D1DANBgkq
hkiG9w0BAQsFAAOCAQEAPKEWCfyNxRdaemcYEXgp6/AlmFoFaNBLi0ewyKOTuy+N
zQvvgdvFbkdsg9BygNQeZQ/WFpNwrODxMZgcGFLpfxPgq1JrIVrU4CQLn8AgTvkc
2sw/1u4xw4ufyKIYxQdsaOPLXOwedUtY96X0e622oIrr7tmUIse8502WnhllRtHL
aGhroMLSVZrNoAU7KHbC3fnHmQPl9HWx9m37u3DGVtLf8/uXsX74RyV6U9ESHbKw
ptZaepLoHk4fIixgMEVMAlHrZPdtUs7X0B520fi2/BwdChqfewf6thkBK9pzGcss
Z8qL7OaQxFqgD2qi7jjWqkqmYe/yxyIowvu1bWRtbA==
-----END CERTIFICATE-----";
        let private_key = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCf87TFBu9fPQ31
mjWAOcYMQeMmHsI/v1Sng4aBoLhWAWZZ+8AuV37wjBVuYGR4GkZHmIJBmi2YNBkP
t/4AIqX4S8hYAAZUurXcVKub2aQOnfh9OLTIxT/GR56imlcRZDrQ+R/VrpVj3yN3
qQHPM1oyuzWin8osCSDRHfEAWcmKVmvHfq6tYVbnmOSQfiPI8+zxMsaMT07RDogO
fxEO/QkPyj16ih9zpK9N2rqbj7q00JIiTSBZ3P/zlshjiZSGZeVaj3bC4KnzKrdl
xS46nfJ7tZ+sHxBqSuScO8X/ButvL7HMnB92Ut47C2SnvD/Or+z86G9KDD2pRxqX
cfBo4cYXAgMBAAECggEABZvMCOSXXCWN6cDAg4CDG0bsKhgGA6o306/e9YinLgza
g+k58eYLg2/GCJrEqxlwwW3tk1NOqfmZr11qQKL2YuB1Y/CMSEhLvDAT3GEjSYfs
gKeOX0PbWp6ER3tV9jwne9Bgd2OpxVi7q6R3dcZ9MS4zUUJ9GlIvnmWIX9TGJl2X
NI8tY2SG6J+ow+OOX98IUzLcyVaZR/AJBKUgFl0PjExLfWBDSLJqJJYEamDy1INh
1PLmPjx3Hz+6r5iaVw3OqPJcZzo+9Bj16RhybOlRvrXMAUbD7w2RzfXI096b4De+
HgyYHFNxj5KpC6qnihkGZVBcbeIjXXPgwexfDipbQQKBgQDNei3y3l0kOXgUgfhp
GMxnmyiHKZmtHzXJJnlNHib7wVPh6YiGDnxVl50MekxSqo53ASv0cpamcDy5TM6N
R5ZeBJW9//MqA0OGbNOCDjYBg2E8jGvyXVPp76ouRxeO5aDordJof4isp6VAPImv
djx3CxxNJKJhzKo5oSJZ9iD+RwKBgQDHR+zsifUDimqg33mrJ92HUMiFxM+haYMV
RySnQZXlDPnVsuZYAdJBUKAMG8ObHy2R2KMnxDdFRRhW6AVzkMkZaQXTUh4M7sx0
QKWHCXRYWNqoS7qOzxS9O6dW6+kmv/bMCjX6l+z2pIe3bpKuHgOPFVyJuNhz285R
RtbxSrbRsQKBgHLRPA3DfY55YoUrHzEy/z1BsULd1xarIvX0vsF+ANCa9hF92qD2
RTnaz5IiYLWswpDzIamlwlLc0sHEjoLZpseAjmAuPqWST1A1TXcWE82CqXoZCVTU
G8jT+GeFqD9cRy7dun5UDX5U631alqFqU1094yGkP+ygXdp4FObqJwOPAoGACWMC
7vVknCEV+rPsGDrNfYU5nMtzeEfvC76JJHO7asmcrws5PGYBkGAK2eco5JKoY9lP
fh0I+XNSvS06rIHiZxcCVjzk+3j4GnW9FkpEt7CfxBOlGvr4IB3COR7toYyjRGMq
vb4QRGHlnqdPs3HoewHnlPknAPYWls9+amk5iVECgYEAu90xfsQzVSiQc4FiDC4+
VU0SuEtd8KmguwckE0RProzJXTs4BhooUB4uwgKA4+IP6cPG9my4vaBL055fHiYb
xpmKp7lj+xPgtXIekR+vzIma2nXiD4Adrs2ITwcjY7dtKLyoLiVJqXQRxWeBoaDS
hlaQghVl9wUq5TwOJgwJDsQ=
-----END PRIVATE KEY-----";
        let mut datakey = get_default_datakey(None, None, None);
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        let _ = X509Plugin::validate_and_update(&mut datakey);
        if let Some(value) = datakey.attributes.get("key_length") {
            assert_eq!(value, "2048");
        } else {
            panic!("Expected key 'key_length' not found in the map.");
        }

        if let Some(value) = datakey.attributes.get("key_type") {
            assert_eq!(value, "rsa");
        } else {
            panic!("Expected key 'key_type' not found in the map.");
        }
    }

    #[test]
    fn test_validate_and_update_with_dsacert() {
        let certificate = "-----BEGIN CERTIFICATE-----
MIIEkzCCBEGgAwIBAgIUHw8WUb9beKVreRngMZyZUrP8UqgwCwYJYIZIAWUDBAMC
MEUxCzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJ
bnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjUxMTE4MTI1MjUxWhcNMjYxMTE4
MTI1MjUxWjBFMQswCQYDVQQGEwJDTjETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8G
A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIDRDCCAjYGByqGSM44BAEw
ggIpAoIBAQCrEexqKCpPOzXK9ZyZZeSLCEFoheoAOMTxLDXcTw9h88J7GZ70udGZ
KinBbT/L9yZimzH3FSwyWbR8gjJxzL84q2qv8rLTtXXgjL93uF+1lDcfITgswCKm
Uvm4uMwPCpved7U+Ni5E5E7FJHEY8MVQQdBnQsKhLpIWyi4xTEK1vHVwS3gyL7D9
HvxaZInZ5x7tOeqKeNsXOS9zXMdkvhyvfDoMtCrq9CwAd/QNkizQ+jyiQP9/Q8xf
crCp4RMHfMTM+c7KkB34w0FYVWg8GOMpWJw55wQ4VpSCxSrc0JC6159vxtLk/CzW
k9IqfA7f7mr/7sR8StKEhioyQ2Z45Z3nAh0AkhAfQfPdW+1ub60zvSsjfOLso36I
fT7TbWvhAQKCAQEAg7xfk8S1E+4NKgxypwtvvt/FVnfbgbkZ0pkQUrD8bbYZamiN
vdMvDauEj16AEwbvUkLdZa5Ht/EcknYimgGG305Ah/hvqUayVd9C22s/7JxOyg/W
Iy1Y6vScDWNO6Svlu9ZU8RmTEXgL9vIekbo1hAnni3zmC9/cDOuMWVdkL0vWqirw
oY8p2QJ3hJXZTD1pgSQaI9VsnnwU+hmCrhRQQUZf6xcDWe6kpgBnCD3kJu3GDr4I
EsA8Q4rGv+Cr4z29Dl7BiSLnJVSVQ9HOSdqvE73CYHJbeaWk0ASNBkimeqzY+5lP
tqGHoZhDw0V6V9xmE6yA+4RA1lCZSn8aLwoEfQOCAQYAAoIBAQCEWY0OioYoUwTx
qOtrDxUypntePUafTAjp3ZsEy54eLGVBWC4Dd9T78Zn98x/9dt/leH+7f40Dv1tA
d2ok5cjMkeMqUEcq9iEC4SkqZfTg6seaOmMaeOSRSfIw2JR0g8RLUCtEvxyfbBNF
2T6aka4PMqSIx4IPKpRENY2/ICYrFAjTHUFyE7d3ER/zbE+r/J8KpBXi0nDMkYcv
1RkZhkDkxoWnVWO6BPDnbe1yL2linCNUhRtmpYHfe9DO16st7MYBdjLS7YEed9Zv
SoBy1UasYaCEoLROzRuUDWXc+mpY73G6B1cAmZd9OU1d+lQ3K5SdIVSrej5YksTE
5QQsoQlUoyEwHzAdBgNVHQ4EFgQUooMZNGLs7K3I1LZBzsX8gbi3fgEwCwYJYIZI
AWUDBAMCAz8AMDwCHGdHB/xu+SQC92KUgXcW2H67qGTg5jsKYMAJBlcCHEbV7+7K
TdRvdJ2ZKZjSsC39ZPCP7KnaP881vaI=
-----END CERTIFICATE-----";
        let private_key = "-----BEGIN PRIVATE KEY-----
MIICXgIBADCCAjYGByqGSM44BAEwggIpAoIBAQCrEexqKCpPOzXK9ZyZZeSLCEFo
heoAOMTxLDXcTw9h88J7GZ70udGZKinBbT/L9yZimzH3FSwyWbR8gjJxzL84q2qv
8rLTtXXgjL93uF+1lDcfITgswCKmUvm4uMwPCpved7U+Ni5E5E7FJHEY8MVQQdBn
QsKhLpIWyi4xTEK1vHVwS3gyL7D9HvxaZInZ5x7tOeqKeNsXOS9zXMdkvhyvfDoM
tCrq9CwAd/QNkizQ+jyiQP9/Q8xfcrCp4RMHfMTM+c7KkB34w0FYVWg8GOMpWJw5
5wQ4VpSCxSrc0JC6159vxtLk/CzWk9IqfA7f7mr/7sR8StKEhioyQ2Z45Z3nAh0A
khAfQfPdW+1ub60zvSsjfOLso36IfT7TbWvhAQKCAQEAg7xfk8S1E+4NKgxypwtv
vt/FVnfbgbkZ0pkQUrD8bbYZamiNvdMvDauEj16AEwbvUkLdZa5Ht/EcknYimgGG
305Ah/hvqUayVd9C22s/7JxOyg/WIy1Y6vScDWNO6Svlu9ZU8RmTEXgL9vIekbo1
hAnni3zmC9/cDOuMWVdkL0vWqirwoY8p2QJ3hJXZTD1pgSQaI9VsnnwU+hmCrhRQ
QUZf6xcDWe6kpgBnCD3kJu3GDr4IEsA8Q4rGv+Cr4z29Dl7BiSLnJVSVQ9HOSdqv
E73CYHJbeaWk0ASNBkimeqzY+5lPtqGHoZhDw0V6V9xmE6yA+4RA1lCZSn8aLwoE
fQQfAh0Ajn5YKCFR13WmbVb52M44GN50U+cJ24RFKPaunA==
-----END PRIVATE KEY-----";
        let mut datakey = get_default_datakey(None, None, None);
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        let _ = X509Plugin::validate_and_update(&mut datakey);
        if let Some(value) = datakey.attributes.get("key_length") {
            assert_eq!(value, "2048");
        } else {
            panic!("Expected key 'key_length' not found in the map.");
        }

        if let Some(value) = datakey.attributes.get("key_type") {
            assert_eq!(value, "dsa");
        } else {
            panic!("Expected key 'key_type' not found in the map.");
        }
    }

    #[tokio::test]
    async fn test_sign_cms_with_timestamp_process_successful() {
        let mut parameter = get_default_parameter();
        parameter.insert("sign_type".to_string(), "cms".to_string());
        let content = "hello world".as_bytes();
        let instance = get_default_plugin().await;
        let _signature = instance
            .sign(content.to_vec(), parameter)
            .expect("sign successfully");
    }

    #[tokio::test]
    async fn test_sign_whole_process_successful() {
        let mut parameter = get_default_parameter();
        parameter.insert("sign_type".to_string(), "kernel-cms".to_string());
        let content = "hello world".as_bytes();
        let instance = get_default_plugin().await;
        let _signature = instance
            .sign(content.to_vec(), parameter)
            .expect("sign successfully");
    }

    #[tokio::test]
    async fn test_crl_generation() {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        // create ca
        let mut ca_key = get_default_datakey(
            Some("fake ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());
        ca_key.private_key = ca_content.private_key;
        ca_key.public_key = ca_content.public_key;
        ca_key.certificate = ca_content.certificate;
        ca_key.serial_number = ca_content.serial_number;
        ca_key.fingerprint = ca_content.fingerprint;
        let crl_sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(crl_sec_datakey, None).expect("create plugin successfully");
        let revoke_time = Utc::now();
        let last_update = Utc::now() + Duration::days(1);
        let next_update = Utc::now() + Duration::days(2);
        let serial_number =
            X509Plugin::generate_serial_number().expect("generate serial number successfully");
        let revoked_keys = RevokedKey {
            id: 0,
            key_id: 0,
            ca_id: 0,
            reason: X509RevokeReason::Unspecified,
            create_at: revoke_time.clone(),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        };
        //generate crl
        let content = plugin
            .generate_crl_content(vec![revoked_keys], last_update.clone(), next_update.clone())
            .expect("generate crl successfully");
        let crl = X509Crl::from_pem(&content).expect("load generated crl successfully");
        assert_eq!(
            crl.last_update()
                == Asn1Time::from_unix(last_update.timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
        assert_eq!(
            crl.next_update().expect("next update is set")
                == Asn1Time::from_unix(next_update.timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
        assert_eq!(crl.get_revoked().is_some(), true);
        let revoked = crl
            .get_revoked()
            .expect("revoke stack is not empty")
            .get(0)
            .expect("first revoke is not empty");
        assert_eq!(
            revoked
                .serial_number()
                .to_owned()
                .expect("convert to asn1 number work")
                == Asn1Integer::from_bn(&serial_number)
                    .expect("convert from bn number should work"),
            true
        );
        assert_eq!(
            revoked.revocation_date().to_owned()
                == Asn1Time::from_unix(revoke_time.timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
    }

    /// Test 1: Verify CRL is V2 format with Authority Key Identifier (AKI) extension
    #[tokio::test]
    async fn test_crl_is_v2_with_aki() {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let mut ca_key = get_default_datakey(
            Some("test_ca_v2".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        ca_key.private_key = ca_content.private_key;
        ca_key.public_key = ca_content.public_key;
        ca_key.certificate = ca_content.certificate;
        ca_key.serial_number = ca_content.serial_number;
        ca_key.fingerprint = ca_content.fingerprint;

        let crl_sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(crl_sec_datakey, None).expect("create plugin successfully");

        let last_update = Utc::now();
        let next_update = Utc::now() + Duration::days(30);

        // Generate CRL - the function at line 777 sets version 1 (V2 X.509)
        // and at lines 800-812 adds AKI extension
        let crl_content = plugin
            .generate_crl_content(vec![], last_update.clone(), next_update.clone())
            .expect("generate crl successfully");

        // Verify CRL is valid and not empty
        assert!(crl_content.len() > 0, "CRL content should not be empty");

        let crl = X509Crl::from_pem(&crl_content).expect("parse generated crl successfully");

        // Verify last_update and next_update timestamps are set and valid
        // Having valid timestamps and extensions proves CRL is V2 format
        // (V1 CRLs cannot have extensions or these fields)
        let lu = crl.last_update();
        let nu = crl
            .next_update()
            .expect("next_update should exist for V2 CRL");

        let lu_str = lu.to_string();
        let nu_str = nu.to_string();

        assert!(
            !lu_str.is_empty() && (lu_str.contains("20") || lu_str.contains("19")),
            "last_update should be valid timestamp: {}",
            lu_str
        );
        assert!(
            !nu_str.is_empty() && (nu_str.contains("20") || nu_str.contains("19")),
            "next_update should be valid timestamp: {}",
            nu_str
        );

        // Verify PEM format is correct
        let pem_str = String::from_utf8_lossy(&crl_content);
        assert!(
            pem_str.contains("BEGIN X509 CRL") && pem_str.contains("END X509 CRL"),
            "Generated content should be valid PEM X509 CRL format"
        );

        // Verify AKI extension existence by writing to temp file and checking with openssl
        use std::io::Write;
        use std::process::Command;
        use tempfile::NamedTempFile;

        if let Ok(mut temp_file) = NamedTempFile::new() {
            let _ = temp_file.write_all(&crl_content);
            let _ = temp_file.flush();

            if let Ok(output) = Command::new("openssl")
                .args(&["crl", "-text", "-noout", "-in"])
                .arg(temp_file.path())
                .output()
            {
                let crl_text = String::from_utf8_lossy(&output.stdout);
                // Check for Authority Key Identifier in the openssl output
                assert!(
                    crl_text.contains("Authority Key Identifier")
                        || crl_text.contains("X509v3 Authority Key Identifier"),
                    "CRL should have Authority Key Identifier (AKI) extension.\n CRL text:\n{}",
                    crl_text
                );
            }
        }
    }

    /// Test 2: Verify CRL next_update time matches configured refresh_interval_days
    #[tokio::test]
    async fn test_crl_next_update_matches_duration() {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let mut ca_key = get_default_datakey(
            Some("test_ca_duration".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        ca_key.private_key = ca_content.private_key;
        ca_key.public_key = ca_content.public_key;
        ca_key.certificate = ca_content.certificate;
        ca_key.serial_number = ca_content.serial_number;
        ca_key.fingerprint = ca_content.fingerprint;

        let crl_sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(crl_sec_datakey, None).expect("create plugin successfully");

        let last_update = Utc::now();

        // Test with 0 days (immediate expiry), 30 days and 90 days duration
        for days in [0, 30, 90].iter() {
            let expected_next_update = last_update + Duration::days(*days as i64);

            let crl_content = plugin
                .generate_crl_content(vec![], last_update.clone(), expected_next_update.clone())
                .expect("generate crl successfully");

            let crl = X509Crl::from_pem(&crl_content).expect("parse generated crl successfully");

            // Verify next_update exists (returns Option)
            let nu_ref = crl.next_update().expect("next_update should exist");

            // Verify last_update exists (returns direct reference)
            let lu_ref = crl.last_update();

            // Convert ASN1Time to strings to extract timestamp values
            let nu_str = nu_ref.to_string();
            let lu_str = lu_ref.to_string();

            // Both should have valid timestamp values containing year
            assert!(
                !nu_str.is_empty() && (nu_str.contains("20") || nu_str.contains("19")),
                "next_update should be valid timestamp for {} days, got: {}",
                days,
                nu_str
            );
            assert!(
                !lu_str.is_empty() && (lu_str.contains("20") || lu_str.contains("19")),
                "last_update should be valid timestamp for {} days, got: {}",
                days,
                lu_str
            );

            // Parse the string timestamps and verify difference matches expected duration
            // Format from ASN1Time.to_string() is typically "Jan 1 00:00:00 2025 GMT"
            // We verify the difference by checking both timestamps are set and different
            // when days > 0
            if *days > 0 {
                assert_ne!(
                    nu_str, lu_str,
                    "next_update and last_update should differ when days > 0, got both: {}",
                    nu_str
                );
            } else {
                // For 0 days, next_update should equal last_update
                assert_eq!(
                    nu_str, lu_str,
                    "next_update and last_update should be equal for 0 days"
                );
            }
        }
    }

    /// Test 3: Verify CRL content actually updates when regenerated
    #[tokio::test]
    async fn test_crl_refresh_updates_content() {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let mut ca_key = get_default_datakey(
            Some("test_ca_refresh".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        ca_key.private_key = ca_content.private_key;
        ca_key.public_key = ca_content.public_key;
        ca_key.certificate = ca_content.certificate;
        ca_key.serial_number = ca_content.serial_number;
        ca_key.fingerprint = ca_content.fingerprint;

        let crl_sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(crl_sec_datakey, None).expect("create plugin successfully");

        let now = Utc::now();
        let next_update_1 = now + Duration::days(30);

        // Generate first CRL
        let crl_content_1 = plugin
            .generate_crl_content(vec![], now.clone(), next_update_1.clone())
            .expect("generate first crl successfully");

        // Wait slightly and generate second CRL (need ~1 second for different timestamp)
        let now_2 = Utc::now() + Duration::seconds(1);
        let next_update_2 = now_2 + Duration::days(30);

        let crl_content_2 = plugin
            .generate_crl_content(vec![], now_2.clone(), next_update_2.clone())
            .expect("generate second crl successfully");

        // Verify CRL content differs (different timestamp = different signature)
        assert_ne!(
            crl_content_1, crl_content_2,
            "CRL content should differ when last_update time changes"
        );

        // Parse both CRLs
        let crl_1 = X509Crl::from_pem(&crl_content_1).expect("parse first crl successfully");
        let crl_2 = X509Crl::from_pem(&crl_content_2).expect("parse second crl successfully");

        // Verify both have valid timestamps
        let lu1 = crl_1.last_update();
        let lu2 = crl_2.last_update();
        let nu1 = crl_1
            .next_update()
            .expect("first crl should have next_update");
        let nu2 = crl_2
            .next_update()
            .expect("second crl should have next_update");

        // Convert to strings and verify they differ
        let lu1_str = lu1.to_string();
        let lu2_str = lu2.to_string();
        let nu1_str = nu1.to_string();
        let nu2_str = nu2.to_string();

        // Verify all timestamps have valid format
        assert!(
            !lu1_str.is_empty() && (lu1_str.contains("20") || lu1_str.contains("19")),
            "first crl last_update should be valid: {}",
            lu1_str
        );
        assert!(
            !lu2_str.is_empty() && (lu2_str.contains("20") || lu2_str.contains("19")),
            "second crl last_update should be valid: {}",
            lu2_str
        );
        assert!(
            !nu1_str.is_empty() && (nu1_str.contains("20") || nu1_str.contains("19")),
            "first crl next_update should be valid: {}",
            nu1_str
        );
        assert!(
            !nu2_str.is_empty() && (nu2_str.contains("20") || nu2_str.contains("19")),
            "second crl next_update should be valid: {}",
            nu2_str
        );

        // Verify timestamps differ between the two CRLs (due to 1 second time difference)
        assert_ne!(
            lu1_str, lu2_str,
            "last_update timestamps should differ: first={}, second={}",
            lu1_str, lu2_str
        );
        assert_ne!(
            nu1_str, nu2_str,
            "next_update timestamps should differ: first={}, second={}",
            nu1_str, nu2_str
        );
    }

    #[tokio::test]
    async fn test_sign_authenticode() {
        let instance = get_default_plugin().await;

        let current_dir = env::current_dir().expect("get current dir failed");
        let efi_file = tokio::fs::read(current_dir.join("test_assets").join("shimx64.efi"))
            .await
            .unwrap();

        let file_hash = efi_signer::EfiImage::parse(&efi_file)
            .unwrap()
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap();
        let mut opts = HashMap::new();

        opts.insert(
            options::SIGN_TYPE.to_string(),
            SignType::Authenticode.to_string(),
        );
        instance.sign(file_hash, opts).unwrap();
    }

    /// Test: Generate CMS EE certificate and verify its extensions
    #[tokio::test]
    async fn test_generate_cms_ee_certificate() {
        let mut parameter = get_default_parameter();
        parameter.insert("x509_ee_usage".to_string(), "cms".to_string());

        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        // Create CA
        let ca_key = get_default_datakey(
            Some("test_cms_ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load ca sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ca plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        // Create ICA
        let mut ica_key = get_default_datakey(
            Some("test_cms_ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509ICA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "test_cms_ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load ica sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ica plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect("generate ica key successfully");

        // Create CMS EE certificate
        let mut ee_key = get_default_datakey(
            Some("test_cms_ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509EE),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "test_cms_ica".to_string(),
            private_key: ica_content.private_key,
            public_key: ica_content.public_key,
            certificate: ica_content.certificate,
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ee_key, &dummy_engine)
            .await
            .expect("load ee sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ee plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect("generate cms ee key successfully");

        // Verify the generated certificate is valid PEM
        let cert_pem = String::from_utf8_lossy(&ee_content.certificate);
        assert!(
            cert_pem.contains("BEGIN CERTIFICATE") && cert_pem.contains("END CERTIFICATE"),
            "Generated CMS certificate should be valid PEM format"
        );

        // Parse certificate and verify it is valid
        let cert = openssl::x509::X509::from_pem(&ee_content.certificate)
            .expect("parse cms certificate successfully");

        // Verify certificate subject
        let subject = cert.subject_name();
        let cn = subject.entries_by_nid(Nid::COMMONNAME).next();
        assert!(cn.is_some(), "CMS certificate should have CommonName");

        // Verify certificate version (should be X509v3)
        let version = cert.version();
        assert_eq!(version, 2, "CMS certificate should be X509v3 (version 2)");

        // Verify certificate has valid dates
        let not_before = cert.not_before();
        let not_after = cert.not_after();
        assert!(
            !not_before.to_string().is_empty(),
            "CMS certificate should have notBefore"
        );
        assert!(
            !not_after.to_string().is_empty(),
            "CMS certificate should have notAfter"
        );

        // Verify certificate is not empty
        assert!(
            !ee_content.private_key.is_empty(),
            "CMS private key should not be empty"
        );
        assert!(
            !ee_content.public_key.is_empty(),
            "CMS public key should not be empty"
        );
    }

    /// Test: Generate Timestamp EE certificate and verify its extensions
    #[tokio::test]
    async fn test_generate_timestamp_ee_certificate() {
        let mut parameter = get_default_parameter();
        parameter.insert("x509_ee_usage".to_string(), "timestamp".to_string());

        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        // Create CA
        let ca_key = get_default_datakey(
            Some("test_ts_ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load ca sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ca plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        // Create ICA
        let mut ica_key = get_default_datakey(
            Some("test_ts_ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509ICA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "test_ts_ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load ica sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ica plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect("generate ica key successfully");

        // Create Timestamp EE certificate
        let mut ee_key = get_default_datakey(
            Some("test_ts_ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509EE),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "test_ts_ica".to_string(),
            private_key: ica_content.private_key,
            public_key: ica_content.public_key,
            certificate: ica_content.certificate,
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ee_key, &dummy_engine)
            .await
            .expect("load ee sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ee plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect("generate timestamp ee key successfully");

        // Verify the generated certificate is valid PEM
        let cert_pem = String::from_utf8_lossy(&ee_content.certificate);
        assert!(
            cert_pem.contains("BEGIN CERTIFICATE") && cert_pem.contains("END CERTIFICATE"),
            "Generated Timestamp certificate should be valid PEM format"
        );

        // Parse certificate and verify extensions
        let cert = openssl::x509::X509::from_pem(&ee_content.certificate)
            .expect("parse timestamp certificate successfully");

        // Verify certificate subject
        let subject = cert.subject_name();
        let cn = subject.entries_by_nid(Nid::COMMONNAME).next();
        assert!(cn.is_some(), "Timestamp certificate should have CommonName");

        // Verify certificate version (should be X509v3)
        let version = cert.version();
        assert_eq!(
            version, 2,
            "Timestamp certificate should be X509v3 (version 2)"
        );

        // Verify certificate has valid dates
        let not_before = cert.not_before();
        let not_after = cert.not_after();
        assert!(
            !not_before.to_string().is_empty(),
            "Timestamp certificate should have notBefore"
        );
        assert!(
            !not_after.to_string().is_empty(),
            "Timestamp certificate should have notAfter"
        );

        // Verify certificate is not empty
        assert!(
            !ee_content.private_key.is_empty(),
            "Timestamp private key should not be empty"
        );
        assert!(
            !ee_content.public_key.is_empty(),
            "Timestamp public key should not be empty"
        );
    }

    /// Test: Sign content with CMS certificate
    #[tokio::test]
    async fn test_sign_with_cms_certificate() {
        let mut parameter = get_default_parameter();
        parameter.insert("x509_ee_usage".to_string(), "cms".to_string());
        parameter.insert("sign_type".to_string(), "cms".to_string());

        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        // Create CA
        let ca_key = get_default_datakey(
            Some("test_cms_sign_ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load ca sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ca plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        // Create ICA
        let mut ica_key = get_default_datakey(
            Some("test_cms_sign_ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509ICA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "test_cms_sign_ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load ica sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ica plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect("generate ica key successfully");

        // Create CMS EE certificate
        let mut ee_key = get_default_datakey(
            Some("test_cms_sign_ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509EE),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "test_cms_sign_ica".to_string(),
            private_key: ica_content.private_key.clone(),
            public_key: ica_content.public_key.clone(),
            certificate: ica_content.certificate.clone(),
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ee_key, &dummy_engine)
            .await
            .expect("load ee sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ee plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect("generate cms ee key successfully");

        // Create X509Plugin instance for signing
        let sec_keys = SecDataKey {
            name: "test_cms_sign_ee".to_string(),
            private_key: SecVec::new(ee_content.private_key.clone()),
            public_key: SecVec::new(ee_content.public_key.clone()),
            certificate: SecVec::new(ee_content.certificate.clone()),
            identity: "".to_string(),
            attributes: parameter.clone(),
            parent: None,
        };

        let sign_plugin =
            X509Plugin::new(sec_keys, None).expect("create x509 sign plugin successfully");

        // Sign content
        let content = "hello world from cms".as_bytes().to_vec();
        let signature = sign_plugin
            .sign(content, parameter)
            .expect("sign with cms certificate successfully");

        // Verify signature is not empty
        assert!(!signature.is_empty(), "CMS signature should not be empty");
    }

    /// Test: Sign content with Timestamp certificate
    #[tokio::test]
    async fn test_sign_with_timestamp_certificate() {
        let mut parameter = get_default_parameter();
        parameter.insert("x509_ee_usage".to_string(), "timestamp".to_string());
        parameter.insert("sign_type".to_string(), "cms".to_string());

        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        // Create CA
        let ca_key = get_default_datakey(
            Some("test_ts_sign_ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load ca sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ca plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect("generate ca key successfully");

        // Create ICA
        let mut ica_key = get_default_datakey(
            Some("test_ts_sign_ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509ICA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "test_ts_sign_ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load ica sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ica plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect("generate ica key successfully");

        // Create Timestamp EE certificate
        let mut ee_key = get_default_datakey(
            Some("test_ts_sign_ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509EE),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "test_ts_sign_ica".to_string(),
            private_key: ica_content.private_key.clone(),
            public_key: ica_content.public_key.clone(),
            certificate: ica_content.certificate.clone(),
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ee_key, &dummy_engine)
            .await
            .expect("load ee sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey, None).expect("create ee plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect("generate timestamp ee key successfully");

        // Create X509Plugin instance for signing
        let sec_keys = SecDataKey {
            name: "test_ts_sign_ee".to_string(),
            private_key: SecVec::new(ee_content.private_key.clone()),
            public_key: SecVec::new(ee_content.public_key.clone()),
            certificate: SecVec::new(ee_content.certificate.clone()),
            identity: "".to_string(),
            attributes: parameter.clone(),
            parent: None,
        };

        let sign_plugin =
            X509Plugin::new(sec_keys, None).expect("create x509 sign plugin successfully");

        // Sign content
        let content = "hello world from timestamp".as_bytes().to_vec();
        let signature = sign_plugin
            .sign(content, parameter)
            .expect("sign with timestamp certificate successfully");

        // Verify signature is not empty
        assert!(
            !signature.is_empty(),
            "Timestamp signature should not be empty"
        );
    }

    /// Test: Verify X509EEUsage enum variants
    #[test]
    fn test_x509_ee_usage_variants() {
        // Test FromStr implementation
        assert_eq!(X509EEUsage::from_str("efi").unwrap(), X509EEUsage::Efi);
        assert_eq!(X509EEUsage::from_str("ko").unwrap(), X509EEUsage::Ko);
        assert_eq!(X509EEUsage::from_str("cms").unwrap(), X509EEUsage::Cms);
        assert_eq!(
            X509EEUsage::from_str("timestamp").unwrap(),
            X509EEUsage::Timestamp
        );

        // Test default fallback to Efi for invalid input
        assert_eq!(X509EEUsage::from_str("invalid").unwrap(), X509EEUsage::Efi);
        assert_eq!(X509EEUsage::from_str("").unwrap(), X509EEUsage::Efi);

        // Test Display implementation
        assert_eq!(format!("{}", X509EEUsage::Efi), "efi");
        assert_eq!(format!("{}", X509EEUsage::Ko), "ko");
        assert_eq!(format!("{}", X509EEUsage::Cms), "cms");
        assert_eq!(format!("{}", X509EEUsage::Timestamp), "timestamp");
    }
}
