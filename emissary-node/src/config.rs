use crate::{
    error::Error,
    su3::{ContentType, FileType, Su3},
    LOG_TARGET,
};

use home::home_dir;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
struct Ntcp2Config {
    port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmissaryConfig {
    ntcp2: Ntcp2Config,
}

/// Router configuration.
pub struct Config {
    /// Base path.
    base_path: PathBuf,

    /// Router info.
    routers: Vec<Vec<u8>>,

    ntcp2_host: Option<String>,
    ntcp2_port: u16,

    /// Static key.
    static_key: Vec<u8>,

    /// Signing key.
    signing_key: Vec<u8>,
}

impl TryFrom<Option<PathBuf>> for Config {
    type Error = Error;

    fn try_from(path: Option<PathBuf>) -> Result<Self, Self::Error> {
        let path = path
            .map_or_else(
                || {
                    let mut path = home_dir()?;
                    (!path.as_os_str().is_empty()).then(|| {
                        path.push(".emissary");
                        path
                    })
                },
                |path| Some(path),
            )
            .ok_or(Error::Custom(String::from("couldn't resolve base path")))?;

        tracing::trace!(
            target: LOG_TARGET,
            ?path,
            "parse router config",
        );

        // if base path doesn't exist, create it and return empty config
        if !path.exists() {
            fs::create_dir_all(&path)?;
            return Ok(Config::new_empty(path)?);
        }

        // read static & signing keys from disk or generate new ones
        let static_key = match Self::load_key(path.clone(), "static") {
            Ok(key) => x25519_dalek::StaticSecret::from(key).to_bytes().to_vec(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to load static key, regenerating",
                );

                Self::create_static_key(path.clone())?
            }
        };

        let signing_key = match Self::load_key(path.clone(), "signing") {
            Ok(key) => ed25519_dalek::SigningKey::from(key).to_bytes().to_vec(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to load signing key, regenerating",
                );

                Self::create_signing_key(path.clone())?
            }
        };

        let mut config = Config::from_keys(path.clone(), static_key, signing_key)?;

        // let config_path = {
        //     let mut path = path.clone();
        //     path.push("router.toml");
        //     path
        // };
        // TODO: parse configuration if it exists
        // // parse configuration, if it exists
        // let mut config = match fs::File::open(&config_path) {
        //     Err(error) => {
        //         tracing::debug!(
        //             target: LOG_TARGET,
        //             ?config_path,
        //             %error,
        //             "router config missing",
        //         );

        //         Config::new_empty(path.clone())?
        //     }
        //     Ok(router) => {
        //         todo!();
        //     }
        // };

        // parse router info
        let router_path = {
            let mut path = path.clone();
            path.push("routers");
            path
        };

        let router_dir = match fs::read_dir(&router_path) {
            Ok(router_dir) => router_dir,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?router_path,
                    ?error,
                    "failed to open router directory, try reseeding",
                );

                return Ok(config);
            }
        };

        config.routers = router_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?;
                let mut file = fs::File::open(dir.path()).ok()?;

                let mut contents = Vec::new();
                file.read_to_end(&mut contents).ok()?;

                Some(contents)
            })
            .collect::<Vec<_>>();

        if config.routers.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                "no routers found, try reseeding the router",
            );
        }

        Ok(config)
    }
}

impl Config {
    /// Create static key.
    fn create_static_key(base_path: PathBuf) -> crate::Result<Vec<u8>> {
        let key = x25519_dalek::StaticSecret::random();
        Self::save_key(base_path, "static", &key).map(|_| key.to_bytes().to_vec())
    }

    /// Create signing key.
    fn create_signing_key(base_path: PathBuf) -> crate::Result<Vec<u8>> {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self::save_key(base_path, "signing", key.as_bytes()).map(|_| key.to_bytes().to_vec())
    }

    /// Save key to disk.
    fn save_key<K: AsRef<[u8]>>(mut path: PathBuf, key_type: &str, key: &K) -> crate::Result<()> {
        path.push(format!("{key_type}.key"));

        let mut file = fs::File::create(path)?;
        file.write_all(key.as_ref())?;

        Ok(())
    }

    /// Load key from disk.
    fn load_key(mut path: PathBuf, key_type: &str) -> crate::Result<[u8; 32]> {
        path.push(format!("{key_type}.key"));

        let mut file = fs::File::open(&path)?;
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;

        Ok(key_bytes)
    }

    /// Create empty config.
    fn new_empty(base_path: PathBuf) -> crate::Result<Self> {
        let static_key = Self::create_static_key(base_path.clone())?;
        let signing_key = Self::create_signing_key(base_path.clone())?;

        let config = EmissaryConfig {
            ntcp2: Ntcp2Config {
                port: 8888u16,
                host: None,
            },
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut path = base_path.clone();
        path.push("router.toml");
        let mut file = fs::File::create(path)?;
        file.write_all(&config.as_bytes())?;

        tracing::info!(
            target: LOG_TARGET,
            ?base_path,
            "emissary starting for the first time",
        );

        Ok(Self {
            base_path,
            routers: Vec::new(),
            ntcp2_host: None,
            ntcp2_port: 8888u16,
            static_key,
            signing_key,
        })
    }

    /// Create new empty config from static & signing keys.
    fn from_keys(
        base_path: PathBuf,
        static_key: Vec<u8>,
        signing_key: Vec<u8>,
    ) -> crate::Result<Self> {
        let config = EmissaryConfig {
            ntcp2: Ntcp2Config {
                port: 8888u16,
                host: None,
            },
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut path = base_path.clone();
        path.push("router.toml");
        let mut file = fs::File::create(path)?;
        file.write_all(&config.as_bytes())?;

        Ok(Self {
            base_path,
            routers: Vec::new(),
            ntcp2_host: None,
            ntcp2_port: 8888u16,
            static_key,
            signing_key,
        })
    }

    /// Reseed router from `file`.
    ///
    /// Returns the number of routers found in the reseed file
    pub fn reseed(&mut self, file: PathBuf) -> crate::Result<usize> {
        tracing::info!(
            target: LOG_TARGET,
            ?file,
            "reseed router from file"
        );

        let parsed = {
            let mut su3_file = fs::File::open(file)?;
            let mut contents = Vec::new();
            su3_file.read_to_end(&mut contents)?;

            Su3::from_bytes(&contents)?
        };

        assert_eq!(parsed.file_type, FileType::Zip);
        assert_eq!(parsed.content_type, ContentType::ReseedData);

        let (FileType::Zip, ContentType::ReseedData) = (parsed.file_type, parsed.content_type)
        else {
            tracing::error!(
                target: LOG_TARGET,
                file_type = ?parsed.file_type,
                content_type = ?parsed.content_type,
                "invalid file type",
            );
            return Err(Error::InvalidData);
        };

        // TODO: memory-mapped file
        let mut test_file = fs::File::create_new("/tmp/routers.zip")?;
        fs::File::write_all(&mut test_file, &parsed.content)?;

        let mut archive =
            zip::ZipArchive::new(test_file).map_err(|error| Error::Custom(error.to_string()))?;

        // create directory for router info if it doesn't exist yet
        let router_path = {
            let mut path = self.base_path.clone();
            path.push("routers");
            fs::create_dir_all(path.clone());

            path
        };

        tracing::trace!(
            target: LOG_TARGET,
            ?router_path,
            "parse router info",
        );

        let num_routers = (0..archive.len()).fold(0usize, |acc, i| {
            let mut file = archive.by_index(i).expect("to exist");
            let Some(outpath) = file.enclosed_name() else {
                return acc;
            };

            if !file.is_file() {
                tracing::warn!(
                    target: LOG_TARGET,
                    "non-file encountered in router info, ignoring",
                );
                return acc;
            }

            let path = {
                let mut path = router_path.clone();
                path.push(&outpath);
                path
            };

            tracing::trace!(
                target: LOG_TARGET,
                router = ?outpath.display(),
                size = ?file.size(),
                "save router to base path",
            );

            let mut outfile = fs::File::create(&path).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();

            acc + 1
        });

        fs::remove_file("/tmp/routers.zip")?;

        Ok(num_routers)
    }
}
