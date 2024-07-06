#![allow(unused)]

use crate::{
    cli::{Arguments, Command},
    config::Config,
    error::Error,
    logger::init_logger,
    tokio_runtime::TokioRuntime,
};

use clap::Parser;
use emissary_lib::router::Router;
use futures::StreamExt;

mod cli;
mod config;
mod error;
mod logger;
mod su3;
mod tokio_runtime;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary";

/// Result type for the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Arguments {
        base_path,
        log,
        command,
    } = Arguments::parse();

    // initialize logger
    init_logger(log)?;

    // parse router config
    // TODO: this should also take any cli params
    let mut config = Config::try_from(base_path)?;

    let router = include_bytes!("/home/altonen/.i2pd/router.info").to_vec();

    match command {
        None => {
            let config: emissary_lib::Config = config.into();
            let mut router = Router::new(TokioRuntime::new(), config, router)
                .await
                .unwrap();

            while let Some(event) = router.next().await {
                tracing::info!("event: {event:?}");
            }
        }
        Some(Command::Reseed { file }) => match config.reseed(file) {
            Ok(num_routers) => tracing::info!(
                target: LOG_TARGET,
                ?num_routers,
                "router reseeded",
            ),
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to reseed router",
                );
                todo!();
            }
        },
    }

    Ok(())
}
