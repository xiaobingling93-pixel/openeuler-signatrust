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

use actix_identity::IdentityMiddleware;
use actix_limitation::{Limiter, RateLimiter};
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware, web, App, HttpServer};
use config::Config;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::Duration as timeDuration;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use crate::infra::database::model::datakey::repository as datakeyRepository;
use crate::infra::database::pool::{create_pool, get_db_connection};
use crate::presentation::handler::control::*;
use crate::util::error::{Error, Result};
use actix_web::cookie::SameSite;
use actix_web::dev::ServiceRequest;
use secstr::SecVec;
use tokio_util::sync::CancellationToken;

use crate::application::datakey::{DBKeyService, KeyService};
use crate::application::user::{DBUserService, UserService};
use crate::domain::datakey::entity::{DataKey, KeyState};
use crate::domain::token::entity::Token;
use crate::domain::user::entity::User;
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;
use crate::infra::sign_backend::factory::SignBackendFactory;
use crate::presentation::handler::control::model::token::dto::CreateTokenDTO;
use crate::presentation::handler::control::model::user::dto::UserIdentity;
use crate::util::key::{file_exists, truncate_string_to_protect_key};

pub struct ControlServer {
    server_config: Arc<RwLock<Config>>,
    user_service: Arc<dyn UserService>,
    key_service: Arc<dyn KeyService>,
    cancel_token: CancellationToken,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "Authorization",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
        )
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::presentation::handler::control::datakey_handler::list_data_key,
        crate::presentation::handler::control::datakey_handler::show_data_key,
        crate::presentation::handler::control::datakey_handler::create_data_key,
        crate::presentation::handler::control::datakey_handler::delete_data_key,
        crate::presentation::handler::control::datakey_handler::cancel_delete_data_key,
        crate::presentation::handler::control::datakey_handler::revoke_data_key,
        crate::presentation::handler::control::datakey_handler::cancel_revoke_data_key,
        crate::presentation::handler::control::datakey_handler::export_public_key,
        crate::presentation::handler::control::datakey_handler::export_certificate,
        crate::presentation::handler::control::datakey_handler::export_crl,
        crate::presentation::handler::control::datakey_handler::enable_data_key,
        crate::presentation::handler::control::datakey_handler::disable_data_key,
        crate::presentation::handler::control::datakey_handler::import_data_key,
        crate::presentation::handler::control::datakey_handler::key_name_identical,

        crate::presentation::handler::control::user_handler::login,
        crate::presentation::handler::control::user_handler::callback,
        crate::presentation::handler::control::user_handler::info,
        crate::presentation::handler::control::user_handler::logout,
        crate::presentation::handler::control::user_handler::new_token,
        crate::presentation::handler::control::user_handler::list_token,
        crate::presentation::handler::control::user_handler::delete_token,

        crate::presentation::handler::control::health_handler::health,
    ),
    components(
        schemas(crate::presentation::handler::control::model::datakey::dto::DataKeyDTO,
                crate::presentation::handler::control::model::datakey::dto::CreateDataKeyDTO,
                crate::presentation::handler::control::model::datakey::dto::ImportDataKeyDTO,
                crate::presentation::handler::control::model::datakey::dto::RevokeCertificateDTO,
                crate::presentation::handler::control::model::datakey::dto::NameIdenticalQuery,
                crate::presentation::handler::control::model::datakey::dto::ListKeyQuery,
                crate::presentation::handler::control::model::token::dto::TokenDTO,
                crate::presentation::handler::control::model::token::dto::CreateTokenDTO,
                crate::presentation::handler::control::model::user::dto::UserIdentity,
                crate::presentation::handler::control::model::user::dto::Code,
                crate::presentation::handler::control::model::datakey::dto::PagedDatakeyDTO,
                crate::presentation::handler::control::model::datakey::dto::PagedMetaDTO,
                crate::util::error::ErrorMessage)
    ),
    modifiers(&SecurityAddon)
)]
struct ControlApiDoc;

impl ControlServer {
    pub async fn new(
        server_config: Arc<RwLock<Config>>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let database = server_config.read()?.get_table("database")?;
        create_pool(&database).await?;
        let data_repository = datakeyRepository::DataKeyRepository::new(get_db_connection()?);
        let sign_backend =
            SignBackendFactory::new_engine(server_config.clone(), get_db_connection()?).await?;
        //initialize repos
        let user_repo = UserRepository::new(get_db_connection()?);
        let token_repo = TokenRepository::new(get_db_connection()?);

        //initialize the service
        let user_service = Arc::new(DBUserService::new(
            user_repo,
            token_repo,
            server_config.clone(),
        )?) as Arc<dyn UserService>;
        let key_service =
            Arc::new(DBKeyService::new(data_repository, sign_backend)) as Arc<dyn KeyService>;
        let server = ControlServer {
            user_service,
            key_service,
            server_config,
            cancel_token,
        };
        Ok(server)
    }

    pub async fn run(&self) -> Result<()> {
        //start actix web server
        let addr: SocketAddr = format!(
            "{}:{}",
            self.server_config
                .read()?
                .get_string("control-server.server_ip")?,
            self.server_config
                .read()?
                .get_string("control-server.server_port")?
        )
        .parse()?;

        let key = self
            .server_config
            .read()?
            .get_string("control-server.cookie_key")?;
        let redis_connection = self
            .server_config
            .read()?
            .get_string("control-server.redis_connection")?;

        info!("control server starts");
        // Start http server
        let user_service = web::Data::from(self.user_service.clone());
        let key_service = web::Data::from(self.key_service.clone());

        key_service.start_key_rotate_loop(self.cancel_token.clone())?;
        key_service.start_key_plugin_maintenance(
            self.cancel_token.clone(),
            self.server_config
                .read()?
                .get_string("control-server.crl_refresh_interval_days")
                .unwrap_or_else(|_| "30".to_string())
                .parse()?,
        )?;
        if let Ok(cfg) = self.server_config.read() {
            let domain = cfg.get_string("control-server.domain_name");
            let kafka_addr = cfg.get_string("control-server.kafka_address");
            let kafka_topic = cfg.get_string("control-server.kafka_topic");
            if let (Ok(domain), Ok(kafka_addr), Ok(kafka_topic)) = (domain, kafka_addr, kafka_topic)
            {
                if let Err(e) =
                    key_service.start_cert_validity_period_check(domain, kafka_addr, kafka_topic)
                {
                    error!("failed to start cert validity period check: {e}");
                    return Err(e);
                }
            }
        }

        //prepare redis store
        let store = RedisSessionStore::new(&redis_connection).await?;
        let limiter = web::Data::new(
            Limiter::builder(&redis_connection)
                .key_by(|req: &ServiceRequest| {
                    if let Some(cookie) = req.cookie("Signatrust") {
                        return Some(cookie.to_string());
                    }
                    if let Some(value) = req.headers().get("Authorization") {
                        return Some(value.to_str().unwrap().to_string());
                    }
                    None
                })
                .limit(
                    self.server_config
                        .read()?
                        .get_string("control-server.limits_per_minute")?
                        .parse()?,
                )
                .period(Duration::from_secs(60))
                .build()
                .unwrap(),
        );

        let openapi = ControlApiDoc::openapi();
        let csrf_protect_key =
            web::Data::new(SecVec::new(truncate_string_to_protect_key(&key).to_vec()));

        let http_server = HttpServer::new(move || {
            App::new()
                //NOTE: csrf protect,following the suggestion from https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
                //there is no need to update csrf cookie for every request
                //in the case of signed double submit cookie ,disable updating csrf token in middleware automatically
                //now and open it if we have to.
                //.wrap(from_fn(UserIdentity::append_csrf_cookie))
                //NOTE: we skipped logging the api health endpoint.
                .wrap(middleware::Logger::default().exclude("/api/health/"))
                .wrap(IdentityMiddleware::default())
                //rate limiter handler
                .wrap(RateLimiter::default())
                // session handler
                .wrap(
                    SessionMiddleware::builder(store.clone(), Key::from(key.as_bytes()))
                        .session_lifecycle(
                            PersistentSession::default().session_ttl(timeDuration::hours(1)),
                        )
                        .cookie_name("Signatrust".to_owned())
                        .cookie_secure(true)
                        .cookie_domain(None)
                        .cookie_same_site(SameSite::Strict)
                        .cookie_path("/".to_owned())
                        .build(),
                )
                .app_data(csrf_protect_key.clone())
                .app_data(key_service.clone())
                .app_data(user_service.clone())
                .app_data(limiter.clone())
                //open api document
                .service(
                    SwaggerUi::new("/api/swagger-ui/{_:.*}")
                        .url("/api-doc/openapi.json", openapi.clone()),
                )
                .service(
                    web::scope("/api/v1")
                        .service(user_handler::get_scope())
                        .service(datakey_handler::get_scope()),
                )
                .service(web::scope("/api").service(health_handler::get_scope()))
        });
        let tls_cert = self
            .server_config
            .read()?
            .get_string("tls_cert")
            .unwrap_or(String::new())
            .to_string();
        let tls_key = self
            .server_config
            .read()?
            .get_string("tls_key")
            .unwrap_or(String::new())
            .to_string();
        if tls_cert.is_empty() || tls_key.is_empty() {
            info!("tls key and cert not configured, control server tls will be disabled");
            http_server.bind(addr)?.run().await?;
        } else {
            if !file_exists(&tls_cert) || !file_exists(&tls_key) {
                return Err(Error::FileFoundError(format!(
                    "tls cert: {} or key: {} file not found",
                    tls_key, tls_cert
                )));
            }
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder
                .set_private_key_file(tls_key, SslFiletype::PEM)
                .unwrap();
            builder.set_certificate_chain_file(tls_cert).unwrap();
            http_server.bind_openssl(addr, builder)?.run().await?;
        }
        Ok(())
    }

    //used for control admin cmd
    pub async fn create_user_token(&self, user: User) -> Result<Token> {
        let user = self.user_service.save(user).await?;
        self.user_service
            .generate_token(
                &UserIdentity::from_user(user.clone()),
                CreateTokenDTO::new("default admin token".to_owned()),
            )
            .await
    }

    //used for control admin cmd
    pub async fn create_keys(&self, data: &mut DataKey, user: UserIdentity) -> Result<DataKey> {
        let key = self.key_service.create(user.clone(), data).await?;
        if data.key_state == KeyState::Disabled {
            self.key_service
                .enable(Some(user), format!("{}", key.id))
                .await?;
        }
        Ok(key)
    }

    //used for control admin cmd
    pub async fn get_key_by_name(&self, name: &str) -> Result<DataKey> {
        self.key_service.get_raw_key_by_name(name).await
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        self.user_service.get_by_email(email).await
    }
}
