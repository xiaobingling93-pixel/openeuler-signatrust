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

use super::traits::SignCommand;
use crate::client::sign_identity;
use crate::util::error::Result;
use clap::Args;
use config::Config;
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc, RwLock};
use tokio::runtime;

use crate::client::file_handler::factory::FileHandlerFactory;
use crate::util::error;
use crate::util::options;
use crate::util::sign::{FileType, KeyType, SignType};
use async_channel::bounded;

use crate::client::load_balancer::factory::ChannelFactory;
use crate::client::worker::assembler::Assembler;
use crate::client::worker::key_fetcher::KeyFetcher;
use crate::client::worker::signer::RemoteSigner;
use crate::client::worker::splitter::Splitter;
use crate::client::worker::traits::SignHandler;
use crate::util::error::Error::CommandProcessFailed;
use crate::util::key::file_exists;
use std::sync::atomic::{AtomicI32, Ordering};

lazy_static! {
    pub static ref FILE_EXTENSION: HashMap<FileType, Vec<&'static str>> = HashMap::from([
        (FileType::Rpm, vec!["rpm", "srpm"]),
        //Generic file can be used for any file
        (FileType::Generic, vec![".*"]),
        (FileType::KernelModule, vec!["ko"]),
        //efi file could be a file without extension
        (FileType::EfiImage, vec![".*"]),
        // ima can be used for any file
        (FileType::ImaEvm, vec![".*"]),
        (FileType::P7s, vec![".*"]),
    ]);
}

#[derive(Args)]
pub struct CommandAdd {
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify the file type for signing")]
    file_type: FileType,
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify the key type for signing")]
    key_type: KeyType,
    #[arg(long)]
    #[arg(help = "specify the key name for signing")]
    key_name: String,
    #[arg(long)]
    #[arg(help = "create detached signature")]
    detached: bool,
    #[arg(
        help = "specify the path which will be used for signing file and directory are supported"
    )]
    path: String,
    #[arg(long)]
    #[arg(value_enum, default_value_t=SignType::Cms)]
    #[arg(
        help = r#"specify the signature type, meaningful when key type is x509,  
        EFI file supports `authenticode` only and KO file supports `cms` and `pkcs7`
        ima evm file supports `rsa-hash` only"#
    )]
    sign_type: SignType,
    #[arg(long)]
    #[arg(
        help = "force create rpm v3 signature, default is false. only support when file type is rpm"
    )]
    rpm_v3: bool,
}

#[derive(Clone)]
pub struct CommandAddHandler {
    worker_threads: usize,
    working_dir: String,
    file_type: FileType,
    key_type: KeyType,
    key_name: String,
    path: PathBuf,
    buffer_size: usize,
    signal: Arc<AtomicBool>,
    config: Arc<RwLock<Config>>,
    detached: bool,
    max_concurrency: usize,
    sign_type: SignType,
    token: Option<String>,
    rpm_v3: bool,
    sign_options: Option<HashMap<String, String>>,
}

impl CommandAddHandler {
    fn get_sign_options(&self) -> HashMap<String, String> {
        if self.sign_options.is_none() {
            HashMap::from([
                (options::DETACHED.to_string(), self.detached.to_string()),
                (options::KEY_TYPE.to_string(), self.key_type.to_string()),
                (options::SIGN_TYPE.to_string(), self.sign_type.to_string()),
                (
                    options::RPM_V3_SIGNATURE.to_string(),
                    self.rpm_v3.to_string(),
                ),
            ])
        } else {
            self.sign_options.clone().unwrap()
        }
    }
    fn collect_file_candidates(&self) -> Result<Vec<sign_identity::SignIdentity>> {
        if self.path.is_dir() {
            let mut container = Vec::new();
            for entry in walkdir::WalkDir::new(self.path.to_str().unwrap()) {
                match entry {
                    Ok(en) => {
                        if en.metadata()?.is_dir() {
                            continue;
                        }
                        if let Some(extension) = en.path().extension() {
                            if self.file_candidates(extension.to_str().unwrap()).is_ok() {
                                container.push(sign_identity::SignIdentity::new(
                                    self.file_type.clone(),
                                    en.path().to_path_buf(),
                                    self.key_type.clone(),
                                    self.key_name.clone(),
                                    self.get_sign_options(),
                                ));
                            }
                        }
                    }
                    Err(err) => {
                        error!("failed to scan file {}, will be skipped", err);
                    }
                }
            }
            return Ok(container);
        } else {
            match self.path.extension() {
                Some(extension) => {
                    if self.file_candidates(extension.to_str().unwrap()).is_ok() {
                        return Ok(vec![sign_identity::SignIdentity::new(
                            self.file_type.clone(),
                            self.path.clone(),
                            self.key_type.clone(),
                            self.key_name.clone(),
                            self.get_sign_options(),
                        )]);
                    }
                }
                None => {
                    if self.file_candidates("").is_ok() {
                        return Ok(vec![sign_identity::SignIdentity::new(
                            self.file_type.clone(),
                            self.path.clone(),
                            self.key_type.clone(),
                            self.key_name.clone(),
                            self.get_sign_options(),
                        )]);
                    }
                }
            }
        }
        Err(error::Error::NoFileCandidateError)
    }

    fn file_candidates(&self, extension: &str) -> Result<bool> {
        let collections = FILE_EXTENSION.get(&self.file_type).ok_or_else(|| {
            error::Error::FileNotSupportError(extension.to_string(), self.file_type.to_string())
        })?;
        for value in collections {
            let re = Regex::new(format!(r"^{}$", value).as_str()).unwrap();
            if re.is_match(extension) {
                return Ok(true);
            }
        }
        Err(error::Error::FileNotSupportError(
            extension.to_string(),
            self.file_type.to_string(),
        ))
    }
}

impl SignCommand for CommandAddHandler {
    type CommandValue = CommandAdd;

    fn new(
        signal: Arc<AtomicBool>,
        config: Arc<RwLock<Config>>,
        command: Self::CommandValue,
    ) -> Result<Self> {
        let mut worker_threads = config.read()?.get_string("worker_threads")?.parse()?;
        if worker_threads == 0 {
            worker_threads = num_cpus::get();
        }
        let working_dir = config.read()?.get_string("working_dir")?;
        if !file_exists(&working_dir) {
            return Err(error::Error::FileFoundError(format!(
                "working dir: {} not exists",
                working_dir
            )));
        }
        let mut token = None;
        if let Ok(t) = config.read()?.get_string("token") {
            if !t.is_empty() {
                token = Some(t);
            }
        }
        Ok(CommandAddHandler {
            worker_threads,
            buffer_size: config.read()?.get_string("buffer_size")?.parse()?,
            working_dir: config.read()?.get_string("working_dir")?,
            file_type: command.file_type,
            key_type: command.key_type,
            key_name: command.key_name,
            path: std::path::PathBuf::from(&command.path),
            signal,
            config: config.clone(),
            detached: command.detached,
            max_concurrency: config.read()?.get_string("max_concurrency")?.parse()?,
            sign_type: command.sign_type,
            token,
            rpm_v3: command.rpm_v3,
            sign_options: None,
        })
    }

    fn validate(&mut self) -> Result<()> {
        let mut options = self.get_sign_options();
        FileHandlerFactory::get_handler(&self.file_type)
            .validate_options(&mut options)
            .expect("failed to validate add signature command options");
        self.sign_options = Some(options);
        Ok(())
    }

    //Signing process are described below.
    //1. fetch all file candidates by walk through the specified path and filter by file extension.
    //2. split files via file handler
    //3. send split content to signer handler which will do remote sign internally
    //4. send encrypted content to file handler for assemble
    //5. collect sign result and print
    //6. wait for async task finish
    //7. all of the worker will not *raise* error but record error inside of object
    //            vector                sign_chn                      assemble_chn             collect_chn
    //  fetcher-----------splitter * N----------remote signer * N---------------assembler * N--------------collector * N
    fn handle(&self) -> Result<bool> {
        let succeed_files = Arc::new(AtomicI32::new(0));
        let failed_files = Arc::new(AtomicI32::new(0));
        let runtime = runtime::Builder::new_multi_thread()
            .worker_threads(self.worker_threads)
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let (split_s, split_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (sign_s, sign_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (assemble_s, assemble_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (collect_s, collect_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let lb_config = self.config.read()?.get_table("server")?;
        let errored = runtime.block_on(async {
            let channel_provider = ChannelFactory::new(&lb_config).await;
            if let Err(err) = channel_provider {
                return Some(err);
            }
            let channel = channel_provider.unwrap().get_channel();
            if let Err(err) = channel {
                return Some(err);
            }
            //fetch datakey attributes
            info!(
                "starting to fetch datakey [{}] {} attribute",
                self.key_type, self.key_name
            );
            let mut key_fetcher = KeyFetcher::new(channel.clone().unwrap(), self.token.clone());
            let key_attributes = match key_fetcher
                .get_key_attributes(&self.key_name, &self.key_type.to_string())
                .await
            {
                Ok(attributes) => attributes,
                Err(err) => return Some(err),
            };
            //collect file candidates
            let files = match self.collect_file_candidates() {
                Ok(f) => f,
                Err(err) => return Some(err),
            };
            info!("starting to sign {} files", files.len());
            let mut signer =
                RemoteSigner::new(channel.unwrap(), self.buffer_size, self.token.clone());
            //split file
            let send_handlers = files
                .into_iter()
                .map(|file| {
                    let task_split_s = split_s.clone();
                    tokio::spawn(async move {
                        let file_name = format!("{}", file.file_path.as_path().display());
                        if let Err(err) = task_split_s.send(file).await {
                            error!("failed to send file for splitting: {}", err);
                        } else {
                            info!("starting to split file: {}", file_name);
                        }
                    })
                })
                .collect::<Vec<_>>();
            //do file split
            let task_sign_s = sign_s.clone();
            let s_key_attributes = key_attributes.clone();
            let split_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = split_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            let mut splitter = Splitter::new(s_key_attributes.clone());
                            splitter.handle(identity, task_sign_s.clone()).await;
                        }
                        Err(_) => {
                            info!("split channel closed");
                            return;
                        }
                    }
                }
            });
            //do remote sign
            let task_assemble_s = assemble_s.clone();
            let sign_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = sign_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            signer.handle(identity, task_assemble_s.clone()).await;
                        }
                        Err(_) => {
                            info!("sign channel closed");
                            return;
                        }
                    }
                }
            });
            //assemble file
            let working_dir = self.working_dir.clone();
            let task_collect_s = collect_s.clone();
            let assemble_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = assemble_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            let mut assembler =
                                Assembler::new(working_dir.clone(), key_attributes.clone());
                            assembler.handle(identity, task_collect_s.clone()).await;
                        }
                        Err(_) => {
                            info!("assemble channel closed");
                            return;
                        }
                    }
                }
            });
            // collect result
            let succeed_files_c = succeed_files.clone();
            let failed_files_c = failed_files.clone();
            let collect_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = collect_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            if identity.error.borrow().clone().is_err() {
                                error!(
                                    "failed to sign file {} due to error {:?}",
                                    identity.file_path.as_path().display(),
                                    identity.error.borrow().clone().err()
                                );
                                failed_files_c.fetch_add(1, Ordering::SeqCst);
                            } else {
                                info!(
                                    "successfully signed file {}",
                                    identity.file_path.as_path().display()
                                );
                                succeed_files_c.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(_) => {
                            info!("collect channel closed");
                            return;
                        }
                    }
                }
            });
            // wait for finish
            for h in send_handlers {
                if let Err(error) = h.await {
                    return Some(CommandProcessFailed(format!(
                        "failed to wait for send handler: {}",
                        error.to_string()
                    )));
                }
            }
            for (key, channel, worker) in [
                ("split", split_s, split_handler),
                ("sign", sign_s, sign_handler),
                ("assemble", assemble_s, assemble_handler),
                ("collect", collect_s, collect_handler),
            ] {
                drop(channel);
                if let Err(error) = worker.await {
                    return Some(CommandProcessFailed(format!(
                        "failed to wait for: {0} handler to finish: {1}",
                        key,
                        error.to_string()
                    )));
                }
            }
            info!(
                "Successfully signed {} files failed {} files",
                succeed_files.load(Ordering::Relaxed),
                failed_files.load(Ordering::Relaxed)
            );
            info!("sign files process finished");
            None
        });
        if let Some(err) = errored {
            return Err(err);
        }
        if failed_files.load(Ordering::Relaxed) != 0 {
            return Ok(false);
        }
        Ok(true)
    }
}
