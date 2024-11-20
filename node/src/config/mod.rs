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

use crate::{
    error::Error,
    su3::{ContentType, FileType, Su3},
    LOG_TARGET,
};

use home::home_dir;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
struct Ntcp2Config {
    enabled: bool,
    port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct I2cpConfig {
    enabled: bool,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmissaryConfig {
    #[serde(default)]
    floodfill: bool,
    ntcp2: Ntcp2Config,
    i2cp: I2cpConfig,
}

/// Router configuration.
pub struct Config {
    /// Base path.
    pub base_path: PathBuf,

    /// I2CP config.
    i2cp_config: Option<emissary::I2cpConfig>,

    /// NTCP2 config.
    ntcp2_config: Option<emissary::Ntcp2Config>,

    /// Router info.
    routers: Vec<Vec<u8>>,

    /// SAMv3 config.
    sam_config: Option<emissary::SamConfig>,

    /// Signing key.
    signing_key: Vec<u8>,

    /// Static key.
    static_key: Vec<u8>,

    /// Should the node be run as a floodfill router.
    pub floodfill: bool,
}

impl Into<emissary::Config> for Config {
    fn into(self) -> emissary::Config {
        emissary::Config {
            static_key: self.static_key,
            signing_key: self.signing_key,
            ntcp2_config: self.ntcp2_config,
            i2cp_config: self.i2cp_config,
            routers: self.routers,
            samv3_config: self.sam_config,
            floodfill: self.floodfill,
        }
    }
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
                    error = %error.to_string(),
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
                    error = %error.to_string(),
                    "failed to load signing key, regenerating",
                );

                Self::create_signing_key(path.clone())?
            }
        };

        let (ntcp2_key, ntcp2_iv) = match Self::load_ntcp2_keys(path.clone()) {
            Ok((key, iv)) => (key, iv),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load ntcp2 iv, regenerating",
                );

                Self::create_ntcp2_keys(path.clone())?
            }
        };

        // try to find `router.toml` and parse it into `EmissaryConfig`
        let router_config = Self::load_router_config(path.clone()).ok();

        let mut config = Config::new(
            path.clone(),
            static_key,
            signing_key,
            ntcp2_key,
            ntcp2_iv,
            router_config,
        )?;

        // fetch known routers
        let router_dir = match fs::read_dir(&path.join("routers")) {
            Ok(router_dir) => router_dir,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
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

    /// Create NTCP2 key and store it on disk.
    fn create_ntcp2_keys(path: PathBuf) -> crate::Result<(Vec<u8>, [u8; 16])> {
        let key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
        let iv = {
            let mut iv = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut iv);

            iv
        };

        // append iv to key and write it to disk
        {
            let mut combined = vec![0u8; 32 + 16];
            combined[..32].copy_from_slice(&key);
            combined[32..].copy_from_slice(&iv);

            let mut file = fs::File::create(path.join("ntcp2.keys"))?;
            file.write_all(combined.as_ref())?;
        }

        Ok((key, iv))
    }

    /// Save key to disk.
    fn save_key<K: AsRef<[u8]>>(path: PathBuf, key_type: &str, key: &K) -> crate::Result<()> {
        let mut file = fs::File::create(path.join(format!("{key_type}.key")))?;
        file.write_all(key.as_ref())?;

        Ok(())
    }

    /// Load key from disk.
    fn load_key(path: PathBuf, key_type: &str) -> crate::Result<[u8; 32]> {
        let mut file = fs::File::open(&path.join(format!("{key_type}.key")))?;
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;

        Ok(key_bytes)
    }

    /// Load NTCP2 key and IV from disk.
    fn load_ntcp2_keys(path: PathBuf) -> crate::Result<(Vec<u8>, [u8; 16])> {
        let key_bytes = {
            let mut file = fs::File::open(&path.join("ntcp2.keys"))?;
            let mut key_bytes = [0u8; 32 + 16];
            file.read_exact(&mut key_bytes)?;

            key_bytes
        };

        Ok((
            key_bytes[..32].to_vec(),
            TryInto::<[u8; 16]>::try_into(&key_bytes[32..]).expect("to succeed"),
        ))
    }

    fn load_router_config(path: PathBuf) -> crate::Result<EmissaryConfig> {
        // parse configuration, if it exists
        let mut file = fs::File::open(&path.join("router.toml"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        toml::from_str::<EmissaryConfig>(&contents).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to parser router config",
            );

            Error::InvalidData
        })
    }

    /// Create empty config.
    ///
    /// Creates a default config with NTCP2 enabled.
    fn new_empty(base_path: PathBuf) -> crate::Result<Self> {
        let static_key = Self::create_static_key(base_path.clone())?;
        let signing_key = Self::create_signing_key(base_path.clone())?;
        let (ntcp2_key, ntcp2_iv) = Self::create_ntcp2_keys(base_path.clone())?;

        let config = EmissaryConfig {
            ntcp2: Ntcp2Config {
                enabled: true,
                port: 8888u16,
                host: None,
            },
            i2cp: I2cpConfig {
                enabled: true,
                port: 7654,
            },
            floodfill: false,
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut file = fs::File::create(base_path.join("router.toml"))?;
        file.write_all(&config.as_bytes())?;

        tracing::info!(
            target: LOG_TARGET,
            ?base_path,
            "emissary starting for the first time",
        );

        Ok(Self {
            base_path,
            routers: Vec::new(),
            ntcp2_config: Some(emissary::Ntcp2Config {
                port: 8888u16,
                host: String::from("127.0.0.1"),
                key: ntcp2_key,
                iv: ntcp2_iv,
            }),
            i2cp_config: Some(emissary::I2cpConfig { port: 7654u16 }),
            sam_config: Some(emissary::SamConfig {
                tcp_port: 7656u16,
                udp_port: 7655u16,
            }),
            static_key,
            signing_key,
            floodfill: false,
        })
    }

    /// Create new [`Config`].
    fn new(
        base_path: PathBuf,
        static_key: Vec<u8>,
        signing_key: Vec<u8>,
        ntcp2_key: Vec<u8>,
        ntcp2_iv: [u8; 16],
        config: Option<EmissaryConfig>,
    ) -> crate::Result<Self> {
        let config = match config {
            Some(config) => config,
            None => {
                let config = EmissaryConfig {
                    ntcp2: Ntcp2Config {
                        enabled: true,
                        port: 8888u16,
                        host: None,
                    },
                    i2cp: I2cpConfig {
                        enabled: true,
                        port: 7654,
                    },
                    floodfill: false,
                };

                let toml_config = toml::to_string(&config).expect("to succeed");
                let mut file = fs::File::create(base_path.join("router.toml"))?;
                file.write_all(&toml_config.as_bytes())?;

                config
            }
        };

        Ok(Self {
            base_path,
            routers: Vec::new(),
            ntcp2_config: Some(emissary::Ntcp2Config {
                port: config.ntcp2.port,
                host: String::from("127.0.0.1"),
                key: ntcp2_key,
                iv: ntcp2_iv,
            }),
            i2cp_config: Some(emissary::I2cpConfig { port: 7654u16 }),
            sam_config: Some(emissary::SamConfig {
                tcp_port: 7656u16,
                udp_port: 7655u16,
            }),
            static_key,
            signing_key,
            floodfill: false,
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
            let _ = fs::create_dir_all(path.clone());

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

    /// Write local `RouterInfo` to disk.
    #[allow(unused)]
    pub fn update_router_info(&self, router_info: Vec<u8>) -> crate::Result<()> {
        let mut file = fs::File::create(self.base_path.join("routerInfo.dat"))?;
        file.write_all(&router_info)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn fresh_boot_directory_created() {
        let dir = tempdir().unwrap();
        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();

        assert!(config.routers.is_empty());
        assert_eq!(config.static_key.len(), 32);
        assert_eq!(config.signing_key.len(), 32);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().port, 8888);
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().host,
            String::from("127.0.0.1")
        );

        let (key, iv) = {
            let mut path = dir.path().to_owned();
            path.push("ntcp2.keys");
            let mut file = File::open(&path).unwrap();

            let mut contents = [0u8; 48];
            file.read_exact(&mut contents).unwrap();

            (
                contents[..32].to_vec(),
                TryInto::<[u8; 16]>::try_into(&contents[32..]).expect("to succeed"),
            )
        };

        assert_eq!(config.ntcp2_config.as_ref().unwrap().key, key);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().iv, iv);
    }

    #[test]
    fn load_configs_correctly() {
        let dir = tempdir().unwrap();

        let (static_key, signing_key, ntcp2_config) = {
            let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
            (config.static_key, config.signing_key, config.ntcp2_config)
        };

        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
        assert_eq!(config.static_key, static_key);
        assert_eq!(config.signing_key, signing_key);
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().port,
            ntcp2_config.as_ref().unwrap().port
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().host,
            ntcp2_config.as_ref().unwrap().host
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().key,
            ntcp2_config.as_ref().unwrap().key
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().iv,
            ntcp2_config.as_ref().unwrap().iv
        );
    }

    #[test]
    fn config_update_works() {
        let dir = tempdir().unwrap();

        // create default config, verify the default ntcp2 port is 8888
        let (ntcp2_key, ntcp2_iv) = {
            let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
            let ntcp2_config = config.ntcp2_config.unwrap();

            assert_eq!(ntcp2_config.port, 8888u16);

            (ntcp2_config.key, ntcp2_config.iv)
        };

        // create new ntcp2 config where the port is different
        let config = EmissaryConfig {
            ntcp2: Ntcp2Config {
                enabled: true,
                port: 1337u16,
                host: None,
            },
            i2cp: I2cpConfig {
                enabled: false,
                port: 0u16,
            },
            floodfill: false,
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all(&config.as_bytes()).unwrap();

        // load the new config
        //
        // verify that ntcp2 key & iv are the same but port is new
        let config = Config::try_from(Some(dir.path().to_owned())).unwrap();
        let ntcp2_config = config.ntcp2_config.unwrap();

        assert_eq!(ntcp2_config.port, 1337u16);
        assert_eq!(ntcp2_config.key, ntcp2_key);
        assert_eq!(ntcp2_config.iv, ntcp2_iv);
    }
}
