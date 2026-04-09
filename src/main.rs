#![allow(dead_code)]

mod cache;
mod dns;
mod dnssec;
mod doh;
mod resolver;
mod server;
mod zone;

use cache::DnsCache;
use parking_lot::RwLock;
use resolver::Resolver;
use serde::Deserialize;
use server::DnsServer;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
    #[serde(default = "default_cache_size")]
    cache_size: usize,
    #[serde(default)]
    enable_dnssec: bool,
    #[serde(default)]
    doh: Option<DohConfig>,
    #[serde(default)]
    zones_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DohConfig {
    #[serde(default = "default_doh_addr")]
    listen_addr: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

fn default_listen_addr() -> String {
    "127.0.0.1:53".to_string()
}

fn default_cache_size() -> usize {
    10000
}

fn default_doh_addr() -> String {
    "127.0.0.1:8443".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: default_listen_addr(),
            cache_size: default_cache_size(),
            enable_dnssec: false,
            doh: None,
            zones_file: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Starting DNS Server v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config = load_config()?;
    info!("Configuration: listen={}, cache_size={}, dnssec={}",
        config.listen_addr, config.cache_size, config.enable_dnssec);

    // Initialize cache
    let cache = Arc::new(DnsCache::new(config.cache_size));

    // Initialize zone store
    let zone_store = Arc::new(RwLock::new(zone::ZoneStore::new()));
    if let Some(ref zones_file) = config.zones_file {
        match std::fs::read_to_string(zones_file) {
            Ok(content) => {
                let zone_config: zone::ZoneConfig = toml::from_str(&content)?;
                zone_store.write().load_config(&zone_config)?;
                info!("Loaded zones from {}", zones_file);
            }
            Err(e) => {
                error!("Failed to load zones file {}: {}", zones_file, e);
            }
        }
    }

    // Initialize resolver
    let resolver = Arc::new(Resolver::new(
        cache.clone(),
        zone_store.clone(),
        config.enable_dnssec,
    ));

    // Start DoH server if configured
    if let Some(ref doh_config) = config.doh {
        let doh_server = Arc::new(doh::DohServer::new(
            resolver.clone(),
            doh_config.listen_addr.clone(),
            doh_config.tls_cert.clone(),
            doh_config.tls_key.clone(),
        ));

        tokio::spawn(async move {
            if let Err(e) = doh_server.run().await {
                error!("DoH server error: {}", e);
            }
        });
    }

    // Start DNS server (UDP + TCP)
    let dns_server = DnsServer::new(resolver, config.listen_addr.clone());
    dns_server.run().await.map_err(|e| -> Box<dyn std::error::Error> { e })?;

    Ok(())
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_paths = [
        "config/config.toml",
        "config.toml",
        "/etc/dns-server/config.toml",
    ];

    for path in &config_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            info!("Loading config from {}", path);
            let config: Config = toml::from_str(&content)?;
            return Ok(config);
        }
    }

    info!("No config file found, using defaults");
    Ok(Config::default())
}
