use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use awc::ClientBuilder;
use hotwatch::notify::event::ModifyKind;
use hotwatch::{Event, EventKind, Hotwatch};
use path_clean::PathClean;
use rustypaste::auth::AuthRuntime;
use rustypaste::config::{Config, ServerConfig};
use rustypaste::middleware::ContentLengthLimiter;
use rustypaste::ownership::{self, PasteScan};
use rustypaste::paste::PasteType;
use rustypaste::server;
use rustypaste::store::{NewPaste, PasteRecord};
use rustypaste::util;
use rustypaste::CONFIG_ENV;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Result as IoResult;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, RwLock};
use std::thread;
use std::time::Duration;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter,
};

const AUTH_PURGE_INTERVAL: Duration = Duration::from_secs(10 * 60);

// Use macros from tracing crate.
#[macro_use]
extern crate tracing;

type SetupResult = (
    Data<RwLock<Config>>,
    ServerConfig,
    Hotwatch,
    mpsc::Receiver<PathBuf>,
);

/// Sets up the application.
///
/// * loads the configuration
/// * initializes the logger
/// * creates the necessary directories
/// * spawns the threads
fn setup(config_folder: &Path) -> IoResult<SetupResult> {
    // Load the .env file.
    dotenvy::dotenv().ok();

    // Initialize logger.
    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse configuration.
    let config_path = match env::var(CONFIG_ENV).ok() {
        Some(path) => {
            unsafe {
                env::remove_var(CONFIG_ENV);
            }
            PathBuf::from(path)
        }
        None => config_folder.join("config.toml"),
    };
    if !config_path.exists() {
        error!(
            "{} is not found, please provide a configuration file.",
            config_path.display()
        );
        std::process::exit(1);
    }
    let config = Config::parse(&config_path).expect("failed to parse config");
    trace!("{:#?}", config);
    config.warn_deprecation();
    let server_config = config.server.clone();
    let paste_config = RwLock::new(config.paste.clone());
    let (config_sender, config_receiver) = mpsc::channel::<Config>();
    let (expired_sender, expired_receiver) = mpsc::channel::<PathBuf>();

    // Create necessary directories.
    fs::create_dir_all(&server_config.upload_path)?;
    for paste_type in &[
        PasteType::Url,
        PasteType::Oneshot,
        PasteType::OneshotUrl,
        PasteType::ProtectedFile,
    ] {
        fs::create_dir_all(paste_type.get_path(&server_config.upload_path)?)?;
    }

    // Set up a watcher for the configuration file changes.
    let mut hotwatch = Hotwatch::new_with_custom_delay(
        config
            .settings
            .as_ref()
            .map(|v| v.refresh_rate)
            .unwrap_or_else(|| Duration::from_secs(1)),
    )
    .expect("failed to initialize configuration file watcher");

    // Hot-reload the configuration file.
    let config = Data::new(RwLock::new(config));
    let cloned_config = Data::clone(&config);
    let config_watcher = move |event: Event| {
        if let (EventKind::Modify(ModifyKind::Data(_)), Some(path)) =
            (event.kind, event.paths.first())
        {
            match Config::parse(path) {
                Ok(config) => match cloned_config.write() {
                    Ok(mut cloned_config) => {
                        match auth_configs_match(&cloned_config, &config) {
                            Ok(true) => {}
                            Ok(false) => {
                                error!(
                                    "Authentication configuration changes require a restart; \
                                     keeping the current configuration."
                                );
                                return;
                            }
                            Err(error) => {
                                error!(
                                    "Cannot compare authentication configuration during reload: \
                                     {error}; keeping the current configuration."
                                );
                                return;
                            }
                        }
                        *cloned_config = config.clone();
                        info!("Configuration has been updated.");
                        if let Err(e) = config_sender.send(config) {
                            error!("Failed to send config for the cleanup routine: {}", e)
                        }
                        cloned_config.warn_deprecation();
                    }
                    Err(e) => {
                        error!("Failed to acquire config: {}", e);
                    }
                },
                Err(e) => {
                    error!("Failed to update config: {}", e);
                }
            }
        }
    };
    hotwatch
        .watch(&config_path, config_watcher)
        .unwrap_or_else(|_| panic!("failed to watch {config_path:?}"));

    // Create a thread for cleaning up expired files.
    let upload_path = server_config.upload_path.clone();
    thread::spawn(move || {
        loop {
            let mut enabled = false;
            if let Some(ref cleanup_config) = paste_config
                .read()
                .ok()
                .and_then(|v| v.delete_expired_files.clone())
            {
                if cleanup_config.enabled {
                    debug!("Running cleanup...");
                    // Clean up expired files
                    for file in util::get_expired_files(&upload_path) {
                        // Delete content file first, then password (prevents unprotected window)
                        match fs::remove_file(&file) {
                            Ok(()) => {
                                info!("Removed expired file: {:?}", file);
                                rustypaste::password::delete_password_file(&file).ok();
                                expired_sender.send(file).ok();
                            }
                            Err(e) => error!("Cannot remove expired file: {}", e),
                        }
                    }

                    // Clean orphaned password files
                    for password_file in util::get_orphaned_password_files(&upload_path) {
                        match fs::remove_file(&password_file) {
                            Ok(()) => info!("Removed orphaned password: {:?}", password_file),
                            Err(e) => error!("Cannot remove orphaned password: {}", e),
                        }
                    }

                    thread::sleep(cleanup_config.interval);
                }
                enabled = cleanup_config.enabled;
            }
            if let Some(new_config) = if enabled {
                config_receiver.try_recv().ok()
            } else {
                config_receiver.recv().ok()
            } {
                match paste_config.write() {
                    Ok(mut paste_config) => {
                        *paste_config = new_config.paste;
                    }
                    Err(e) => {
                        error!("Failed to update config for the cleanup routine: {}", e);
                    }
                }
            }
        }
    });

    Ok((config, server_config, hotwatch, expired_receiver))
}

fn auth_configs_match(current: &Config, candidate: &Config) -> serde_json::Result<bool> {
    if current.auth.is_none() && candidate.auth.is_none() {
        return Ok(true);
    }
    Ok(auth_config_fingerprint(current)? == auth_config_fingerprint(candidate)?)
}

#[allow(deprecated)]
fn auth_config_fingerprint(config: &Config) -> serde_json::Result<serde_json::Value> {
    let sorted_tokens = |tokens: &Option<HashSet<String>>| {
        let mut tokens = tokens
            .as_ref()
            .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        tokens.sort();
        tokens
    };
    Ok(serde_json::json!({
        "auth": serde_json::to_value(&config.auth)?,
        "public_server_url": config.server.url,
        "upload_path": config.server.upload_path,
        "legacy_auth_token": config.server.auth_token,
        "legacy_auth_tokens": sorted_tokens(&config.server.auth_tokens),
        "legacy_delete_tokens": sorted_tokens(&config.server.delete_tokens),
    }))
}

fn retain_existing_pastes(
    scan: &mut PasteScan,
    existing_pastes: impl IntoIterator<Item = PasteRecord>,
) {
    let mut paths: HashSet<PathBuf> = scan
        .pastes
        .iter()
        .map(|paste| paste.storage_path.clone())
        .collect();
    for paste in existing_pastes {
        if paths.insert(paste.storage_path.clone()) {
            scan.pastes.push(NewPaste {
                owner_principal_id: paste.owner_principal_id,
                public_filename: paste.public_filename,
                storage_path: paste.storage_path,
                paste_type: paste.paste_type,
                created_at: paste.created_at,
                size_bytes: paste.size_bytes,
                expires_at: paste.expires_at,
                content_hash: paste.content_hash,
            });
        }
    }
}

#[actix_web::main]
async fn main() -> IoResult<()> {
    // Set up the application.
    let (config, server_config, _hotwatch, expired_receiver) = setup(&PathBuf::new())?;
    let auth_runtime = {
        let config = config
            .read()
            .map_err(|_| std::io::Error::other("cannot acquire config"))?
            .clone();
        AuthRuntime::initialize(&config)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .map(Data::new)
    };
    if let Some(runtime) = &auth_runtime {
        let mut paste_scan = ownership::scan_pastes(&server_config.upload_path)?;
        if paste_scan.skipped_entries > 0 {
            let existing_pastes = runtime
                .store
                .list_all_pastes()
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            retain_existing_pastes(&mut paste_scan, existing_pastes);
            warn!(
                "Skipped {} unreadable paste entries; retaining existing metadata while \
                 reconciling readable entries.",
                paste_scan.skipped_entries
            );
        }
        let reconciliation = runtime
            .store
            .reconcile_pastes(&paste_scan.pastes)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        info!(
            "Reconciled paste ownership metadata: {} inserted, {} removed",
            reconciliation.inserted, reconciliation.removed
        );
        runtime
            .store
            .purge_expired()
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;

        let store = runtime.store.clone();
        actix_web::rt::spawn(async move {
            loop {
                match expired_receiver.try_recv() {
                    Ok(path) => {
                        if let Err(error) = store.delete_paste_by_storage_path(&path.clean()).await
                        {
                            error!("Cannot remove expired paste metadata: {}", error);
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        actix_web::rt::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
            }
        });

        let store = runtime.store.clone();
        actix_web::rt::spawn(async move {
            loop {
                actix_web::rt::time::sleep(AUTH_PURGE_INTERVAL).await;
                match store.purge_expired().await {
                    Ok(0) => {}
                    Ok(count) => debug!("Purged {count} expired authentication records."),
                    Err(error) => error!("Cannot purge expired authentication records: {error}"),
                }
            }
        });
    }

    // Create an HTTP server.
    let mut http_server = HttpServer::new(move || {
        let http_client = ClientBuilder::new()
            .timeout(
                server_config
                    .timeout
                    .unwrap_or_else(|| Duration::from_secs(30)),
            )
            .disable_redirects()
            .finish();
        let app = App::new()
            .app_data(Data::clone(&config))
            .app_data(Data::new(http_client))
            .wrap(Logger::new(
                "%{r}a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T",
            ))
            .wrap(ContentLengthLimiter::new(server_config.max_content_length));
        let app = if let Some(auth_runtime) = &auth_runtime {
            app.app_data(Data::clone(auth_runtime))
                .configure(rustypaste::auth_server::configure_routes)
        } else {
            app
        };
        app.configure(server::configure_routes)
    })
    .bind(&server_config.address)?;

    // Set worker count for the server.
    if let Some(workers) = server_config.workers {
        http_server = http_server.workers(workers);
    }

    // Run the server.
    info!("Server is running at {}", server_config.address);
    http_server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustypaste::config::AuthConfig;
    use serde_json::json;

    fn auth_config(client_id: &str) -> AuthConfig {
        serde_json::from_value(json!({
            "database_path": "state/auth.sqlite3",
            "oidc": {
                "issuer_url": "https://identity.example.com",
                "client_id": client_id,
                "client_secret": "secret"
            }
        }))
        .expect("valid auth config")
    }

    #[test]
    fn hot_reload_accepts_identical_auth_configuration() {
        let current = Config {
            auth: Some(auth_config("rustypaste")),
            ..Config::default()
        };
        let candidate = current.clone();

        assert!(auth_configs_match(&current, &candidate).expect("serialize auth config"));
    }

    #[test]
    fn hot_reload_rejects_authentication_mode_or_setting_changes() {
        let current = Config::default();
        let enabled = Config {
            auth: Some(auth_config("rustypaste")),
            ..Config::default()
        };
        assert!(!auth_configs_match(&current, &enabled).expect("serialize auth config"));

        let mut changed = enabled.clone();
        changed.auth = Some(auth_config("different-client"));
        assert!(!auth_configs_match(&enabled, &changed).expect("serialize auth config"));

        let mut changed_legacy_tokens = enabled.clone();
        changed_legacy_tokens.server.auth_tokens = Some([String::from("replacement-token")].into());
        assert!(!auth_configs_match(&enabled, &changed_legacy_tokens)
            .expect("serialize authentication config"));

        let mut changed_runtime_path = enabled.clone();
        changed_runtime_path.server.upload_path = PathBuf::from("different-upload-path");
        assert!(!auth_configs_match(&enabled, &changed_runtime_path)
            .expect("serialize authentication config"));

        let mut changed_public_url = enabled.clone();
        changed_public_url.server.url = Some(String::from("https://other.example.com"));
        assert!(!auth_configs_match(&enabled, &changed_public_url)
            .expect("serialize authentication config"));
    }

    #[test]
    fn incomplete_scans_retain_existing_unreadable_paste_metadata() {
        let scanned = NewPaste {
            owner_principal_id: None,
            public_filename: String::from("scanned.txt"),
            storage_path: PathBuf::from("upload/scanned.txt"),
            paste_type: PasteType::File,
            created_at: 10,
            size_bytes: 7,
            expires_at: None,
            content_hash: String::from("scanned-hash"),
        };
        let unreadable = PasteRecord {
            id: 1,
            owner_principal_id: Some(42),
            public_filename: String::from("unreadable.txt"),
            storage_path: PathBuf::from("upload/unreadable.txt"),
            paste_type: PasteType::ProtectedFile,
            created_at: 20,
            updated_at: 21,
            size_bytes: 11,
            expires_at: None,
            content_hash: String::from("unreadable-hash"),
        };
        let mut scan = PasteScan {
            pastes: vec![scanned],
            skipped_entries: 1,
        };

        retain_existing_pastes(&mut scan, [unreadable]);

        assert_eq!(2, scan.pastes.len());
        assert!(scan.pastes.iter().any(|paste| {
            paste.storage_path == Path::new("upload/unreadable.txt")
                && paste.owner_principal_id == Some(42)
        }));
    }
}
