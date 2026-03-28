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

use actix_web::{web, HttpResponse, Responder, Result, Scope};
use std::str::FromStr;

use super::model::user::dto::UserIdentity;
use crate::application::datakey::KeyService;
use crate::domain::datakey::entity::{
    DataKey, DatakeyPaginationQuery, KeyType, Visibility, X509RevokeReason,
};
use crate::presentation::handler::control::model::datakey::dto::{
    CRLContent, CertificateContent, CreateDataKeyDTO, DataKeyDTO, ImportDataKeyDTO, ListKeyQuery,
    NameIdenticalQuery, PagedDatakeyDTO, PublicKeyContent, RevokeCertificateDTO,
};
use crate::util::error::Error;
use crate::util::key::get_datakey_full_name;
use validator::Validate;

/// Create new key
///
/// This will generate either a private/public pgp key pairs or a x509 private/public/cert keys.
/// ## Naming convention
/// The name of the key should be unique and ":" is not allowed in the name.
/// ## Generate pgp key
/// To generate a pgp key the required parameters in `attributes` are:
/// 1. **digest_algorithm**: the digest algorithm used for pgp, for example: sha2_256
/// 2. **email**: email address used for identify the pgp key,
/// 3. **key_length**: the private key length, for example, 2048,
/// 4. **key_type**: the algorithm of private key, for example, rsa or dsa.
/// 5. **passphrase**: (optional) password of the key
/// ### Request body example:
/// ```json
/// {
///   "name": "test-pgp",
///   "description": "hello world",
///   "key_type": "pgp",
///   "visibility": "public",
///   "attributes": {
///     "digest_algorithm": "sha2_256",
///     "key_type": "rsa",
///     "key_length": "2048",
///     "email": "test@openeuler.org",
///     "passphrase": "password"
///   },
///   "expire_at": "2024-05-12 22:10:57+08:00"
/// }
/// ```
///
/// ## Generate x509 key
/// To generate a x509 key the required parameters in `attributes` are:
/// 1. **digest_algorithm**: the digest algorithm used for x509 key, for example: sha2_256
/// 2. **key_length**: the private key length, for example, 2048,
/// 3. **key_type**: the algorithm of private key, for example, rsa or dsa.
/// 4. **common_name**: common name (commonName, CN), used for certificate.
/// 5. **country_name**: country (countryName, C), used for certificate.
/// 6. **locality**: locality (locality, L), used for certificate.
/// 7. **organization**: organization (organizationName, O), used for certificate.
/// 8. **organizational_unit**: organizational unit (organizationalUnitName, OU), used for certificate.
/// 9. **province_name**: state or province name (stateOrProvinceName, ST), used for certificate.
/// 10. **x509_ee_usage**: the usage of end entity certificate, for example: ko, efi, cms, or timestamp. The AuthorityKeyIdentifier and KeyUsage differs between them.
///
/// There are three different keys regarding X509, they are:
///     1. X509CA: Root CA key, used for issue intermediate CA certificate.
///     2. X509ICA: Intermediate CA key, used for issue end entity certificate.
///     3. X509EE: End entity key, used for sign object.
/// You have to specify the parent_id: when you create a X509ICA or X509EE key.
///
/// The x509_ee_usage supports the following values:
///     - **ko**: Kernel module signing certificate
///     - **efi**: EFI image signing certificate
///     - **cms**: CMS (Cryptographic Message Syntax) signing certificate
///     - **timestamp**: Time Stamp Authority (TSA) certificate for timestamp signing
///
/// ### Request body example:
/// ```json
/// {
///   "name": "test-x509",
///   "description": "hello world",
///   "key_type": "x509CA",
///   "parent_id": "1111",
///   "visibility": "public",
///   "attributes": {
///     "digest_algorithm": "sha2_256",
///     "key_type": "rsa",
///     "key_length": "2048",
///     "common_name": "common name",
///     "organizational_unit": "organizational_unit",
///     "organization": "organization",
///     "locality": "locality",
///     "province_name": "province_name",
///     "country_name": "country_name",
///     "x509_ee_usage": "cms"
///   },
///   "expire_at": "2024-05-12 22:10:57+08:00"
/// }
/// ```
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys -d '{}'
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/",
    request_body = CreateDataKeyDTO,
    security(
    ("Authorization" = [])
    ),
    responses(
    (status = 201, description = "Key successfully imported", body = DataKeyDTO),
    (status = 400, description = "Bad request", body = ErrorMessage),
    (status = 401, description = "Unauthorized", body = ErrorMessage),
    (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn create_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    datakey: web::Json<CreateDataKeyDTO>,
) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::create_from(datakey.0, user.clone())?;
    Ok(HttpResponse::Created().json(DataKeyDTO::try_from(
        key_service.into_inner().create(user, &mut key).await?,
    )?))
}

/// Get all available keys from database.
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/keys/?key_type=xxxx&visibility=xxxxx
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/",
    params(
        ListKeyQuery
    ),
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "List available keys", body = [PagedDatakeyDTO]),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn list_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    key: web::Query<ListKeyQuery>,
) -> Result<impl Responder, Error> {
    key.validate()?;
    //test visibility matched.
    Visibility::from_parameter(key.visibility.clone())?;
    let keys = key_service
        .into_inner()
        .get_all(user.id, DatakeyPaginationQuery::from(key.into_inner()))
        .await?;
    Ok(HttpResponse::Ok().json(PagedDatakeyDTO::try_from(keys)?))
}

/// Get detail of specific key by id or name from database
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/keys/{id_or_name}
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/{id_or_name}",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "List available keys", body = DataKeyDTO),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn show_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let key = key_service
        .into_inner()
        .get_one(Some(user), id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(DataKeyDTO::try_from(key)?))
}

/// Delete specific key by id or name from database
///
/// only **disabled** key can be deleted.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/request_delete
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/request_delete",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully deleted"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn delete_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    key_service
        .into_inner()
        .request_delete(user, id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok())
}

/// Cancel deletion of specific key by id or name from database
///
/// only **pending_delete** key can be canceled.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/cancel_delete
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/cancel_delete",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key deletion canceled successfully"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn cancel_delete_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    key_service
        .into_inner()
        .cancel_delete(user, id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok())
}

/// Revoke a certificate by id or name from database.
///
/// only **disabled** or **pending_revoke** and X509EE/X509ICA key can be revoked.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/request_revoke
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/request_revoke",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    request_body = RevokeCertificateDTO,
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully revoked"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn revoke_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
    reason: web::Json<RevokeCertificateDTO>,
) -> Result<impl Responder, Error> {
    key_service
        .into_inner()
        .request_revoke(
            user,
            id_or_name.into_inner(),
            X509RevokeReason::from_str(&reason.reason)?,
        )
        .await?;
    Ok(HttpResponse::Ok())
}

/// Cancel revoke a certificate by id or name from database.
///
/// only **pending_revoke** and X509EE/X509ICA key can be cancel revoked.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/cancel_revoke
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/cancel_revoke",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully deleted"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn cancel_revoke_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    key_service
        .into_inner()
        .cancel_revoke(user, id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok())
}

/// Get public key content of specific key by id or name from database
/// Note: Please add authentication token when requesting a private key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/public_key
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/{id_or_name}/public_key",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    responses(
        (status = 200, description = "Key successfully exported",),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn export_public_key(
    user: Option<UserIdentity>,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let data_key = key_service
        .export_one(user, id_or_name.into_inner())
        .await?;
    if data_key.key_type != KeyType::OpenPGP {
        return Ok(HttpResponse::Forbidden().finish());
    }
    Ok(HttpResponse::Ok()
        .content_type("text/plain")
        .body(PublicKeyContent::try_from(data_key)?.content))
}

/// Get certificate content of specific key by id or name from database
/// Note: Please add authentication token when requesting a private key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/certificate
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/{id_or_name}/certificate",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    responses(
        (status = 200, description = "Key successfully exported"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]

async fn export_certificate(
    user: Option<UserIdentity>,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let data_key = key_service
        .export_one(user, id_or_name.into_inner())
        .await?;
    if data_key.key_type == KeyType::OpenPGP {
        return Ok(HttpResponse::Forbidden().finish());
    }
    Ok(HttpResponse::Ok()
        .content_type("text/plain")
        .body(CertificateContent::try_from(data_key)?.content))
}

/// Get Client Revoke List content of specific key(cert) by id or name from database
/// Note: Please add authentication token when requesting a private key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/crl
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/{id_or_name}/crl",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    responses(
        (status = 200, description = "Key successfully exported"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn export_crl(
    user: Option<UserIdentity>,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    //note: we could not get any crl content by a openpgp id.
    let crl_content = key_service
        .export_cert_crl(user, id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok()
        .content_type("text/plain")
        .body(CRLContent::try_from(crl_content)?.content))
}

/// Enable specific key by id or name from database
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/enable
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/enable",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully enabled"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn enable_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    key_service
        .enable(Some(user), id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok())
}

/// Disable specific key by id or name from database
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id_or_name}/actions/disable
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id_or_name}/actions/disable",
    params(
        ("id_or_name" = String, Path, description = "Key id or key name"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully disabled"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn disable_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    id_or_name: web::Path<String>,
) -> Result<impl Responder, Error> {
    key_service
        .disable(Some(user), id_or_name.into_inner())
        .await?;
    Ok(HttpResponse::Ok())
}

/// Check whether a key name already exists
///
/// Use this API to check whether the key name exists in database, for private key, either {email}:{key_name} or {key_name} format is acceptable.
/// `name` are required
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X HEAD https://domain:port/api/v1/keys/name_identical?name=xxx&visibility=xxxxx
/// ```
#[utoipa::path(
    head,
    path = "/api/v1/keys/name_identical",
    params(
        NameIdenticalQuery
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Name does not exist"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 409, description = "Conflict in name")
    )
)]
async fn key_name_identical(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    name_exist: web::Query<NameIdenticalQuery>,
) -> Result<impl Responder, Error> {
    name_exist.validate()?;
    let visibility = Visibility::from_parameter(name_exist.visibility.clone())?;
    let key_name = get_datakey_full_name(&name_exist.name, &user.email, &visibility)?;
    match key_service
        .into_inner()
        .get_raw_key_by_name(&key_name)
        .await
    {
        Ok(_) => Ok(HttpResponse::Conflict()),
        Err(_) => Ok(HttpResponse::Ok()),
    }
}

/// Import key
///
/// Use this API to import public/private openpgp or x509 keys
/// ## Import openPGP keys
/// `private_key` and `public_key` are required, and the content are represented in armored text format, for example:
/// ```text
///  -----BEGIN PGP PUBLIC KEY BLOCK-----
///  xsFNBGRDujMBEADwXafQySUIUvuO0e7vTzgW8KkgzAFDmR7CO8tVplcQS03oZmrm
///  ZhhjV+MnfsONMVzrAvusDIF4YnKSXGJI8Y4A21hsK6CV+1PxqCpcGqDQ88H1Gtd5
///  ........skipped content.......
///  vTw1M8qqdjRpJhdF8kNXZITlaMkLOwZuL3QvDvEORw41o8zgSN1ryQuN/HtSLOJr
///  IcJ//T9nn8hCPxkMZE2T7JBEZBQwbzGjI5nUZV6nS6caINfXtkoRbta1SXcoRBSe
///  L0fZUKYcKURCAbLmz0bcrOsDBqnK
///  =c1i2
/// -----END PGP PUBLIC KEY BLOCK-----
/// ```
/// you need to specify the `digest_algorithm`, `key_type`, `expire` and `key_length` in the `attributes` as well,
/// passphrase **MUST** be specified for accessing the imported keys which specified passphrase when generating.
/// ```json
/// "attributes": {
///     "digest_algorithm": "sha2_256"
///     "passphrase": "husheng@1234"
///     "key_type": "rsa",
///     "key_length": "2048",
///     "expire_at": "2024-07-12 22:10:57+08:00"
/// }
/// ```
/// ## Import openSSL x509 keys
/// `certificate` and `private` are required, and the content are represented in PEM format, for example:
/// ```text
/// -----BEGIN PRIVATE KEY-----
/// MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDrd/0ui/bc5PJS
/// Yo5eS9hD2M91NrJZPiF+vEdq/vOSypac9XukLjkhj1zADU2h35b1nMQoi0bG7SNr
/// ........skipped content.......
/// XTYUPye7CKt33tFhHYKj7EHvZmHkbmskpXdCiHpTZd4u84lwvH/acHfJ0Fqh0pV3
/// IHehlWfHhjCxtw5Kzl3ncrHA
/// -----END PRIVATE KEY-----
/// ```
/// you need to specify the `digest_algorithm`, `key_type`, `expire` and `key_length` in the `attributes` as well,
/// ```json
/// "attributes": {
///     "digest_algorithm": "sha2_256"
///     "key_type": "rsa",
///     "key_length": "2048",
///     "expire_at": "2024-07-12 22:10:57+08:00"
/// }
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/import
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/import",
    request_body = ImportDataKeyDTO,
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 201, description = "Key successfully imported", body = DataKeyDTO),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn import_data_key(
    user: UserIdentity,
    key_service: web::Data<dyn KeyService>,
    datakey: web::Json<ImportDataKeyDTO>,
) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::import_from(datakey.0, user)?;
    Ok(HttpResponse::Created().json(DataKeyDTO::try_from(
        key_service.into_inner().import(&mut key).await?,
    )?))
}

pub fn get_scope() -> Scope {
    web::scope("/keys")
        .service(
            web::resource("/")
                .route(web::get().to(list_data_key))
                .route(web::post().to(create_data_key)),
        )
        .service(web::resource("/import").route(web::post().to(import_data_key)))
        .service(web::resource("/name_identical").route(web::head().to(key_name_identical)))
        .service(web::resource("/{id_or_name}").route(web::get().to(show_data_key)))
        .service(web::resource("/{id_or_name}/public_key").route(web::get().to(export_public_key)))
        .service(
            web::resource("/{id_or_name}/certificate").route(web::get().to(export_certificate)),
        )
        .service(web::resource("/{id_or_name}/crl").route(web::get().to(export_crl)))
        .service(
            web::resource("/{id_or_name}/actions/enable").route(web::post().to(enable_data_key)),
        )
        .service(
            web::resource("/{id_or_name}/actions/disable").route(web::post().to(disable_data_key)),
        )
        .service(
            web::resource("/{id_or_name}/actions/request_delete")
                .route(web::post().to(delete_data_key)),
        )
        .service(
            web::resource("/{id_or_name}/actions/cancel_delete")
                .route(web::post().to(cancel_delete_data_key)),
        )
        .service(
            web::resource("/{id_or_name}/actions/request_revoke")
                .route(web::post().to(revoke_data_key)),
        )
        .service(
            web::resource("/{id_or_name}/actions/cancel_revoke")
                .route(web::post().to(cancel_revoke_data_key)),
        )
}
