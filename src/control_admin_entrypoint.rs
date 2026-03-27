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

#![allow(dead_code)]

use crate::domain::datakey::entity::DataKey;
use crate::domain::datakey::entity::{KeyType as EntityKeyTpe, KeyType};
use crate::domain::user::entity::User;
use crate::presentation::handler::control::model::datakey::dto::CreateDataKeyDTO;
use crate::presentation::handler::control::model::user::dto::UserIdentity;
use crate::util::error::Result;
use chrono::{Duration, Utc};
use clap::Args;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use tokio_util::sync::CancellationToken;
use validator::Validate;

mod application;
mod domain;
mod infra;
mod presentation;
mod util;

#[macro_use]
extern crate log;

#[derive(Parser)]
#[command(name = "signatrust-admin")]
#[command(author = "TommyLike <tommylikehu@gmail.com>")]
#[command(version = "0.10")]
#[command(about = "Administrator command for signatrust server", long_about = None)]
pub struct App {
    #[arg(short, long)]
    #[arg(
        help = "path of configuration file, './client.toml' relative to working directory be used in default"
    )]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Create default admin and admin token", long_about = None)]
    CreateAdmin(CommandAdmin),
    #[command(about = "Generate keys for signing", long_about = None)]
    GenerateKeys(Box<CommandGenerateKeys>),
}

#[derive(Args)]
pub struct CommandAdmin {
    #[arg(long)]
    #[arg(help = "specify the email of admin")]
    email: String,
}

#[derive(Args)]
pub struct CommandGenerateKeys {
    #[arg(long)]
    #[arg(help = "specify the name of this key pairs")]
    name: String,
    #[arg(long)]
    #[arg(help = "specify the the description of this key pairs")]
    description: String,
    #[arg(long)]
    #[arg(help = "specify the type of internal key used for keys generation, ie, rsa")]
    param_key_type: String,
    #[arg(long)]
    #[arg(help = "specify the type of internal key used for keys generation, ie, 2048")]
    param_key_size: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the type of digest algorithm used for signing, ie, sha1")]
    digest_algorithm: String,
    //pgp specific parameters
    #[arg(long)]
    #[arg(help = "specify the email used for openPGP key generation. ")]
    param_pgp_email: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the passphrase for openPGP key generation. ")]
    param_pgp_passphrase: Option<String>,
    //x509 specific parameters
    #[arg(long)]
    #[arg(help = "specify the 'CommonName' used for x509 key generation. ")]
    param_x509_common_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'OrganizationalUnit' used for x509 key generation. ")]
    param_x509_organizational_unit: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'Organization' used for x509 key generation. ")]
    param_x509_organization: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'Locality' used for x509 key generation. ")]
    param_x509_locality: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'ProvinceName' used for x509 key generation. ")]
    param_x509_province_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'CountryName' used for x509 key generation. ")]
    param_x509_country_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the name of the CA or ICA which used for cert issuing. ")]
    param_x509_parent_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the usage of x509 EE certificate, ie, efi, ko, cms, timestamp")]
    param_x509_ee_usage: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the email of admin which this key bounds to")]
    email: String,
    #[arg(long)]
    #[arg(help = "specify th type of key")]
    key_type: String,
    #[arg(long)]
    #[arg(help = "specify th visibility of key")]
    visibility: String,
}

fn generate_keys_parameters(command: &CommandGenerateKeys) -> HashMap<String, String> {
    let mut attributes = HashMap::new();
    attributes.insert("key_type".to_string(), command.param_key_type.clone());
    if command.param_key_size.is_some() {
        attributes.insert(
            "key_length".to_string(),
            command.param_key_size.clone().unwrap(),
        );
    }
    attributes.insert(
        "digest_algorithm".to_string(),
        command.digest_algorithm.clone(),
    );
    let key_type = EntityKeyTpe::from_str(&command.key_type).unwrap();
    if key_type == EntityKeyTpe::OpenPGP {
        attributes.insert(
            "email".to_string(),
            command.param_pgp_email.clone().unwrap(),
        );
        attributes.insert(
            "passphrase".to_string(),
            command.param_pgp_passphrase.clone().unwrap(),
        );
    } else {
        attributes.insert(
            "common_name".to_string(),
            command.param_x509_common_name.clone().unwrap(),
        );
        attributes.insert(
            "country_name".to_string(),
            command.param_x509_country_name.clone().unwrap(),
        );
        attributes.insert(
            "locality".to_string(),
            command.param_x509_locality.clone().unwrap(),
        );
        attributes.insert(
            "province_name".to_string(),
            command.param_x509_province_name.clone().unwrap(),
        );
        attributes.insert(
            "organization".to_string(),
            command.param_x509_organization.clone().unwrap(),
        );
        attributes.insert(
            "organizational_unit".to_string(),
            command.param_x509_organizational_unit.clone().unwrap(),
        );
        attributes.insert(
            "x509_ee_usage".to_string(),
            command
                .param_x509_ee_usage
                .clone()
                .unwrap_or("efi".to_string()),
        );
    }
    attributes
}

#[tokio::main]
async fn main() -> Result<()> {
    //prepare config and logger
    env_logger::init();
    let app = App::parse();
    let path = app.config.unwrap_or(format!(
        "{}/{}",
        env::current_dir().expect("current dir not found").display(),
        "config/server.toml"
    ));
    let server_config = util::config::ServerConfig::new(path);
    //cancel token will never been used/canceled here cause it's only used for background threads in control server instance.
    let control_server = presentation::server::control_server::ControlServer::new(
        server_config.config,
        CancellationToken::new(),
    )
    .await?;
    //handle commands
    match app.command {
        Some(Commands::CreateAdmin(create_admin)) => {
            let token = control_server
                .create_user_token(User::new(create_admin.email.clone())?)
                .await?;
            info!("[Result]: Administrator {} has been successfully created with token {} will expire {}", &create_admin.email, &token.token, &token.expire_at)
        }
        Some(Commands::GenerateKeys(generate_keys)) => {
            let user = control_server
                .get_user_by_email(&generate_keys.email)
                .await?;

            let now = Utc::now();
            let mut key = CreateDataKeyDTO {
                name: generate_keys.name.clone(),
                description: generate_keys.description.clone(),
                attributes: generate_keys_parameters(&generate_keys),
                key_type: generate_keys.key_type.clone(),
                parent_id: None,
                visibility: Some(generate_keys.visibility.clone()),
                expire_at: format!("{}", now + Duration::days(30)),
            };
            if generate_keys.key_type == KeyType::X509CA.to_string() {
                key.expire_at = format!("{}", now + Duration::days(365));
            }
            if generate_keys.key_type == KeyType::X509ICA.to_string() {
                key.expire_at = format!("{}", now + Duration::days(180));
            }
            if let Some(id) = generate_keys.param_x509_parent_name {
                let data_key = control_server.get_key_by_name(&id).await?;
                key.parent_id = Some(data_key.id);
            }
            key.validate()?;

            let keys = control_server
                .create_keys(
                    &mut DataKey::create_from(key, UserIdentity::from_user(user.clone()))?,
                    UserIdentity::from_user(user),
                )
                .await?;
            info!(
                "[Result]: Keys {} type {} has been successfully generated",
                &keys.name, &generate_keys.key_type
            )
        }
        None => {}
    };
    Ok(())
}
