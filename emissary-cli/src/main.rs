// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{cli::Arguments, config::Config, error::Error, signal::SignalHandler};

use anyhow::anyhow;
use clap::Parser;
use emissary_core::router::{Router, RouterEvent};
use emissary_util::{reseeder::Reseeder, runtime::tokio::Runtime, su3::ReseedRouterInfo};
use futures::StreamExt;

use std::{fs::File, io::Write};

mod cli;
mod config;
mod error;
mod logger;
mod signal;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary";

/// Reseeding threshold.
const RESEED_THRESHOLD: usize = 25usize;

/// Result type for the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let mut handler = SignalHandler::new();

    // initialize logger with any logging directive given as a cli argument
    let handle = init_logger!(arguments.log.clone());

    // parse router config and merge it with cli options
    let mut config = Config::try_from(arguments.base_path.clone())?.merge(&arguments);

    // reinitialize the logger with any directives given in the configuration file
    init_logger!(config.log.clone(), handle);

    // try to reseed the router if there aren't enough known routers
    if (config.routers.len() < RESEED_THRESHOLD && !config.reseed.disable)
        || arguments.reseed.force_reseed.unwrap_or(false)
    {
        tracing::info!(
            target: LOG_TARGET,
            num_routers = ?config.routers.len(),
            num_needed = ?RESEED_THRESHOLD,
            forced_reseed = ?arguments.reseed.force_reseed.unwrap_or(false),
            "reseed router"
        );

        match Reseeder::reseed(config.reseed.hosts.clone()).await {
            Ok(routers) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    num_routers = ?routers.len(),
                    "router reseeded",
                );

                routers.into_iter().for_each(|ReseedRouterInfo { name, router_info }| {
                    if let Ok(mut file) =
                        File::create(config.base_path.join(format!("routers/{name}")))
                    {
                        let _ = file.write_all(&router_info);
                    }

                    config.routers.push(router_info);
                });
            }
            Err(error) if config.routers.is_empty() => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to reseed and no routers available",
                );
                return Err(anyhow!("no routers available"));
            }
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to reseed, trying to start router anyway",
            ),
        };
    }

    let path = config.base_path.clone();
    let (mut router, local_router_info) = Router::<Runtime>::new(config.into()).await.unwrap();

    // TODO: ugly
    let mut file = File::create(path.join("router.info"))?;
    file.write_all(&local_router_info)?;

    loop {
        tokio::select! {
            _ = handler.next() => {
                router.shutdown();
            }
            event = router.next() => match event {
                None => return Ok(()),
                Some(RouterEvent::Shutdown) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        "emissary shut down",
                    );
                    return Ok(());
                }
            }
        }
    }
}
