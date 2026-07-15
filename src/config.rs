use crate::mime::MimeMatcher;
use crate::random::RandomURLConfig;
use crate::{AUTH_TOKENS_FILE_ENV, AUTH_TOKEN_ENV, DELETE_TOKENS_FILE_ENV, DELETE_TOKEN_ENV};
use byte_unit::Byte;
use config::{self, ConfigError};
use path_clean::PathClean as _;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(90 * 24 * 60 * 60);

fn default_auth_timeout() -> Duration {
    DEFAULT_AUTH_TIMEOUT
}

fn default_true() -> bool {
    true
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        String::from("openid"),
        String::from("profile"),
        String::from("email"),
    ]
}

/// Configuration values.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Configuration settings.
    #[serde(rename = "config")]
    pub settings: Option<Settings>,
    /// Server configuration.
    pub server: ServerConfig,
    /// Paste configuration.
    pub paste: PasteConfig,
    /// Landing page configuration.
    pub landing_page: Option<LandingPageConfig>,
    /// OIDC authentication and ownership configuration.
    pub auth: Option<AuthConfig>,
}

/// A secret configuration value whose debug representation is always redacted.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a new secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes the secret value to code that must use it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns whether the secret is empty after trimming whitespace.
    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// OIDC authentication, persistent session, and service account settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    /// SQLite database path. This should not be inside the upload directory.
    pub database_path: PathBuf,
    /// Rolling browser session idle timeout.
    #[serde(default = "default_auth_timeout", with = "humantime_serde")]
    pub session_idle_timeout: Duration,
    /// Rolling CLI/API token idle timeout.
    #[serde(default = "default_auth_timeout", with = "humantime_serde")]
    pub token_idle_timeout: Duration,
    /// Whether browser cookies carry the Secure attribute.
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
    /// Explicitly permit HTTP issuer/server URLs for local development.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// OIDC provider settings.
    pub oidc: OidcConfig,
    /// Claim-based authorization settings.
    #[serde(default)]
    pub authorization: AuthorizationConfig,
    /// Named non-human principals and their static credentials.
    #[serde(default)]
    pub service_accounts: BTreeMap<String, ServiceAccountConfig>,
}

/// OIDC provider and client settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL.
    pub issuer_url: String,
    /// OIDC client identifier.
    pub client_id: String,
    /// OIDC client secret.
    pub client_secret: SecretString,
    /// Requested OIDC scopes. `openid` is always required.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

/// Claim gates for login and administrator access.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthorizationConfig {
    /// Claims that every OIDC identity must satisfy to log in.
    #[serde(default)]
    pub required_claims: ClaimRules,
    /// Claims that grant administrator access when all rules match.
    #[serde(default)]
    pub admin_claims: ClaimRules,
}

/// Expected values for a single top-level OIDC claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ClaimValues {
    /// One acceptable string value.
    One(String),
    /// Any of these string values is acceptable.
    Any(Vec<String>),
}

impl<'de> Deserialize<'de> for ClaimValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            One(String),
            Any(Vec<String>),
        }

        match Repr::deserialize(deserializer)? {
            Repr::One(value) => Ok(Self::One(value)),
            Repr::Any(values) if values.is_empty() => {
                Err(de::Error::custom("claim value list cannot be empty"))
            }
            Repr::Any(values) => Ok(Self::Any(values)),
        }
    }
}

impl ClaimValues {
    fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Any(values) => values,
        }
    }
}

/// A set of top-level claim rules. Keys use AND semantics and values use OR semantics.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimRules(BTreeMap<String, ClaimValues>);

impl ClaimRules {
    /// Creates claim rules from their configured key/value mapping.
    pub fn new(rules: BTreeMap<String, ClaimValues>) -> Self {
        Self(rules)
    }

    /// Returns whether no claim constraints are configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether all configured keys match at least one acceptable value.
    ///
    /// Only top-level string claims and arrays of strings participate in matching.
    pub fn matches(&self, claims: &JsonMap<String, JsonValue>) -> bool {
        self.0.iter().all(|(key, expected)| {
            let Some(actual) = claims.get(key) else {
                return false;
            };
            let expected = expected.values();
            match actual {
                JsonValue::String(value) => expected.contains(value),
                JsonValue::Array(values) => values.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| expected.iter().any(|item| item == value))
                }),
                _ => false,
            }
        })
    }

    fn validate(&self, label: &str) -> Result<(), String> {
        for (key, values) in &self.0 {
            if key.trim().is_empty() {
                return Err(format!("{label} contains an empty claim key"));
            }
            if values.values().iter().any(|value| value.trim().is_empty()) {
                return Err(format!("{label}.{key} contains an empty claim value"));
            }
        }
        Ok(())
    }
}

/// A named service account's credential source and privileges.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceAccountConfig {
    /// Inline static bearer token.
    pub token: Option<SecretString>,
    /// File containing the bearer token.
    pub token_file: Option<PathBuf>,
    /// Environment variable containing the bearer token.
    pub token_env: Option<String>,
    /// Whether this service account has administrator access.
    #[serde(default)]
    pub admin: bool,
}

impl ServiceAccountConfig {
    /// Loads this service account's token from its configured source.
    pub fn resolve_token(&self) -> Result<SecretString, String> {
        let value = if let Some(token) = &self.token {
            token.expose().to_string()
        } else if let Some(path) = &self.token_file {
            read_to_string(path).map_err(|error| {
                format!(
                    "failed to read service account token file {}: {error}",
                    path.display()
                )
            })?
        } else if let Some(variable) = &self.token_env {
            env::var(variable).map_err(|error| {
                format!(
                    "failed to read service account token environment variable {variable}: {error}"
                )
            })?
        } else {
            return Err(String::from("service account has no token source"));
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(String::from("service account token cannot be empty"));
        }
        Ok(SecretString::new(value))
    }

    fn validate(&self, name: &str) -> Result<(), String> {
        let sources = usize::from(self.token.is_some())
            + usize::from(self.token_file.is_some())
            + usize::from(self.token_env.is_some());
        if sources != 1 {
            return Err(format!(
                "service account {name:?} must configure exactly one of token, token_file, or token_env"
            ));
        }
        if self.token.as_ref().is_some_and(SecretString::is_empty) {
            return Err(format!("service account {name:?} token cannot be empty"));
        }
        if self
            .token_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(format!(
                "service account {name:?} token_file cannot be empty"
            ));
        }
        if self
            .token_env
            .as_ref()
            .is_some_and(|variable| variable.trim().is_empty())
        {
            return Err(format!(
                "service account {name:?} token_env cannot be empty"
            ));
        }
        Ok(())
    }
}

impl AuthorizationConfig {
    /// Returns whether the claims satisfy the login gate.
    pub fn allows(&self, claims: &JsonMap<String, JsonValue>) -> bool {
        self.required_claims.matches(claims)
    }

    /// Returns whether the claims grant administrator access.
    ///
    /// An empty administrator rule set never grants administrator access.
    pub fn is_admin(&self, claims: &JsonMap<String, JsonValue>) -> bool {
        !self.admin_claims.is_empty() && self.admin_claims.matches(claims)
    }
}

impl AuthConfig {
    /// Validates authentication settings against the public server settings.
    pub fn validate(&self, server: &ServerConfig) -> Result<(), String> {
        if self.database_path.as_os_str().is_empty() {
            return Err(String::from("[auth].database_path is required"));
        }
        if self.session_idle_timeout.is_zero() {
            return Err(String::from(
                "[auth].session_idle_timeout must be greater than zero",
            ));
        }
        if self.token_idle_timeout.is_zero() {
            return Err(String::from(
                "[auth].token_idle_timeout must be greater than zero",
            ));
        }

        let server_url = server
            .url
            .as_deref()
            .ok_or_else(|| String::from("[server].url is required when [auth] is configured"))?;
        let server_url = validate_auth_url("[server].url", server_url, self.allow_insecure_http)?;
        validate_auth_url(
            "[auth.oidc].issuer_url",
            &self.oidc.issuer_url,
            self.allow_insecure_http,
        )?;
        if server_url.scheme() != "https" && self.secure_cookies {
            return Err(String::from(
                "[auth].secure_cookies must be false when local HTTP is enabled",
            ));
        }

        if !server.upload_path.as_os_str().is_empty() {
            let current_dir = env::current_dir()
                .map_err(|error| format!("cannot resolve authentication paths: {error}"))?;
            let database_path = absolute_clean_path(&current_dir, &self.database_path);
            let upload_path = absolute_clean_path(&current_dir, &server.upload_path);
            if database_path.starts_with(&upload_path) {
                return Err(String::from(
                    "[auth].database_path must be outside [server].upload_path",
                ));
            }
        }

        if self.oidc.client_id.trim().is_empty() {
            return Err(String::from("[auth.oidc].client_id cannot be empty"));
        }
        if self.oidc.client_secret.is_empty() {
            return Err(String::from("[auth.oidc].client_secret cannot be empty"));
        }
        if self.oidc.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(String::from(
                "[auth.oidc].scopes cannot contain empty values",
            ));
        }
        if !self.oidc.scopes.iter().any(|scope| scope == "openid") {
            return Err(String::from(
                "[auth.oidc].scopes must contain the openid scope",
            ));
        }

        self.authorization
            .required_claims
            .validate("[auth.authorization.required_claims]")?;
        self.authorization
            .admin_claims
            .validate("[auth.authorization.admin_claims]")?;

        for (name, account) in &self.service_accounts {
            if name.trim().is_empty() {
                return Err(String::from("service account names cannot be empty"));
            }
            account.validate(name)?;
        }
        Ok(())
    }
}

fn validate_auth_url(label: &str, value: &str, allow_insecure_http: bool) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| format!("{label} is not a valid URL: {error}"))?;
    if url.scheme() != "https" && !(allow_insecure_http && url.scheme() == "http") {
        return Err(format!(
            "{label} must use HTTPS (or HTTP with [auth].allow_insecure_http for local development)"
        ));
    }
    if url.host_str().is_none() {
        return Err(format!("{label} must have a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{label} must not contain URL credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{label} must not contain a query or fragment"));
    }
    Ok(url)
}

fn absolute_clean_path(current_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.clean()
    } else {
        current_dir.join(path).clean()
    }
}

/// General settings for configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Refresh rate of the configuration file.
    #[serde(with = "humantime_serde")]
    pub refresh_rate: Duration,
}

/// Server configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    /// The socket address to bind.
    pub address: String,
    /// URL that can be used to access the server externally.
    pub url: Option<String>,
    /// Number of workers to start.
    pub workers: Option<usize>,
    /// Maximum content length.
    pub max_content_length: Byte,
    /// Storage path.
    pub upload_path: PathBuf,
    /// Maximum upload directory size.
    pub max_upload_dir_size: Option<Byte>,
    /// Request timeout.
    #[serde(default, with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// Authentication token.
    #[deprecated(note = "use [server].auth_tokens instead")]
    pub auth_token: Option<String>,
    /// Authentication tokens.
    pub auth_tokens: Option<HashSet<String>>,
    /// Expose version.
    pub expose_version: Option<bool>,
    /// Landing page text.
    #[deprecated(note = "use the [landing_page] table")]
    pub landing_page: Option<String>,
    /// Landing page content-type.
    #[deprecated(note = "use the [landing_page] table")]
    pub landing_page_content_type: Option<String>,
    /// Handle spaces either via encoding or replacing.
    pub handle_spaces: Option<SpaceHandlingConfig>,
    /// Path of the JSON index.
    pub expose_list: Option<bool>,
    /// Authentication tokens for deleting.
    pub delete_tokens: Option<HashSet<String>>,
    /// Enable security hardening headers (X-Content-Type-Options, Content-Security-Policy).
    pub hardening: Option<bool>,
}

/// Enum representing different strategies for handling spaces in filenames.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceHandlingConfig {
    /// Represents encoding spaces (e.g., using "%20").
    Encode,
    /// Represents replacing spaces with underscores.
    Replace,
}

impl SpaceHandlingConfig {
    /// Processes the given filename based on the specified space handling strategy.
    pub fn process_filename(&self, file_name: &str) -> String {
        match self {
            Self::Encode => file_name.replace(' ', "%20"),
            Self::Replace => file_name.replace(' ', "_"),
        }
    }
}

/// Landing page configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LandingPageConfig {
    /// Landing page text.
    pub text: Option<String>,
    /// Landing page file.
    pub file: Option<String>,
    /// Landing page content-type
    pub content_type: Option<String>,
}

/// Paste configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PasteConfig {
    /// Random URL configuration.
    pub random_url: Option<RandomURLConfig>,
    /// Default file extension.
    pub default_extension: String,
    /// Media type override options.
    #[serde(default)]
    pub mime_override: Vec<MimeMatcher>,
    /// Media type blacklist.
    #[serde(default)]
    pub mime_blacklist: Vec<String>,
    /// Additional MIME types to render as text/plain when serving files.
    #[serde(default)]
    pub text_mime_overrides: Vec<String>,
    /// Allow duplicate uploads.
    pub duplicate_files: Option<bool>,
    /// Default expiry time.
    #[serde(default, with = "humantime_serde")]
    pub default_expiry: Option<Duration>,
    /// Delete expired files.
    pub delete_expired_files: Option<CleanupConfig>,
}

/// Cleanup configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CleanupConfig {
    /// Enable cleaning up.
    pub enabled: bool,
    /// Interval between clean-ups.
    #[serde(default, with = "humantime_serde")]
    pub interval: Duration,
}

/// Type of access token.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TokenType {
    /// Token for authentication.
    Auth,
    /// Token for DELETE endpoint.
    Delete,
}

impl Config {
    /// Parses the config file and returns the values.
    pub fn parse(path: &Path) -> Result<Config, ConfigError> {
        let config: Self = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::default().separator("__"))
            .build()?
            .try_deserialize()?;
        config.validate().map_err(ConfigError::Message)?;
        Ok(config)
    }

    /// Validates configuration relationships that deserialization cannot express.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(auth) = &self.auth {
            auth.validate(&self.server)?;
        }
        Ok(())
    }

    /// Retrieves all configured auth/delete tokens.
    pub fn get_tokens(&self, token_type: TokenType) -> Option<HashSet<String>> {
        let mut tokens = match token_type {
            TokenType::Auth => {
                let mut tokens: HashSet<_> = self.server.auth_tokens.clone().unwrap_or_default();

                #[allow(deprecated)]
                if let Some(token) = &self.server.auth_token {
                    tokens.insert(token.to_string());
                }
                if let Ok(env_token) = env::var(AUTH_TOKEN_ENV) {
                    tokens.insert(env_token);
                }
                if let Ok(env_path) = env::var(AUTH_TOKENS_FILE_ENV) {
                    match read_to_string(&env_path) {
                        Ok(s) => {
                            s.lines().filter(|l| !l.trim().is_empty()).for_each(|l| {
                                tokens.insert(l.to_string());
                            });
                        }
                        Err(e) => {
                            error!(
                                "failed to read tokens from authentication file ({env_path}) ({e})"
                            );
                        }
                    };
                }

                tokens
            }
            TokenType::Delete => {
                let mut tokens: HashSet<_> = self.server.delete_tokens.clone().unwrap_or_default();

                if let Ok(env_token) = env::var(DELETE_TOKEN_ENV) {
                    tokens.insert(env_token);
                }

                if let Ok(env_path) = env::var(DELETE_TOKENS_FILE_ENV) {
                    match read_to_string(&env_path) {
                        Ok(s) => {
                            s.lines().filter(|l| !l.trim().is_empty()).for_each(|l| {
                                tokens.insert(l.to_string());
                            });
                        }
                        Err(e) => {
                            error!("failed to read deletion tokens from file ({env_path}) ({e})");
                        }
                    };
                }

                tokens
            }
        };

        // filter out blank tokens
        tokens.retain(|v| !v.trim().is_empty());
        Some(tokens).filter(|v| !v.is_empty())
    }

    /// Print deprecation warnings.
    #[allow(deprecated)]
    pub fn warn_deprecation(&self) {
        if self.server.auth_token.is_some() {
            warn!("[server].auth_token is deprecated, please use [server].auth_tokens");
        }
        if self.server.landing_page.is_some() {
            warn!("[server].landing_page is deprecated, please use [landing_page].text");
        }
        if self.server.landing_page_content_type.is_some() {
            warn!(
                "[server].landing_page_content_type is deprecated, please use [landing_page].content_type"
            );
        }
        if let Some(random_url) = &self.paste.random_url {
            if random_url.enabled.is_some() {
                warn!(
                    "[paste].random_url.enabled is deprecated, disable it by commenting out [paste].random_url"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::env;

    fn valid_auth() -> AuthConfig {
        AuthConfig {
            database_path: PathBuf::from("./auth.sqlite3"),
            session_idle_timeout: DEFAULT_AUTH_TIMEOUT,
            token_idle_timeout: DEFAULT_AUTH_TIMEOUT,
            secure_cookies: true,
            allow_insecure_http: false,
            oidc: OidcConfig {
                issuer_url: String::from("https://identity.example.com"),
                client_id: String::from("rustypaste"),
                client_secret: SecretString::new("oidc-secret"),
                scopes: default_oidc_scopes(),
            },
            authorization: AuthorizationConfig::default(),
            service_accounts: BTreeMap::new(),
        }
    }

    fn secure_server() -> ServerConfig {
        ServerConfig {
            url: Some(String::from("https://paste.example.com")),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn test_parse_config() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("SERVER__ADDRESS", "0.0.1.1");
        }
        let config = Config::parse(&config_path)?;
        assert_eq!("0.0.1.1", config.server.address);
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_deprecated_config() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("SERVER__ADDRESS", "0.0.1.1");
        }
        let mut config = Config::parse(&config_path)?;
        config.paste.random_url = Some(RandomURLConfig {
            enabled: Some(true),
            ..RandomURLConfig::default()
        });
        assert_eq!("0.0.1.1", config.server.address);
        config.warn_deprecation();
        Ok(())
    }

    #[test]
    fn test_space_handling() {
        let processed_filename =
            SpaceHandlingConfig::Replace.process_filename("file with spaces.txt");
        assert_eq!("file_with_spaces.txt", processed_filename);
        let encoded_filename = SpaceHandlingConfig::Encode.process_filename("file with spaces.txt");
        assert_eq!("file%20with%20spaces.txt", encoded_filename);
    }

    #[test]
    fn test_get_tokens() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("AUTH_TOKEN", "env_auth");
            env::set_var("DELETE_TOKEN", "env_delete");
        }
        let mut config = Config::parse(&config_path)?;
        // empty tokens will be filtered
        config.server.auth_tokens =
            Some(["may_the_force_be_with_you".to_string(), "".to_string()].into());
        config.server.delete_tokens = Some(["i_am_your_father".to_string(), "".to_string()].into());
        assert_eq!(
            Some(HashSet::from([
                "env_auth".to_string(),
                "may_the_force_be_with_you".to_string()
            ])),
            config.get_tokens(TokenType::Auth)
        );
        assert_eq!(
            Some(HashSet::from([
                "env_delete".to_string(),
                "i_am_your_father".to_string()
            ])),
            config.get_tokens(TokenType::Delete)
        );
        unsafe {
            env::remove_var("AUTH_TOKEN");
            env::remove_var("DELETE_TOKEN");
        }

        // `get_tokens` returns `None` if no tokens are configured
        config.server.auth_tokens = Some(["  ".to_string()].into());
        config.server.delete_tokens = Some(HashSet::new());
        assert_eq!(None, config.get_tokens(TokenType::Auth));
        assert_eq!(None, config.get_tokens(TokenType::Delete));

        Ok(())
    }

    #[test]
    fn auth_config_defaults_to_ninety_day_idle_timeouts() -> Result<(), ConfigError> {
        let auth: AuthConfig = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
                database_path = "auth.sqlite3"
                [oidc]
                issuer_url = "https://identity.example.com"
                client_id = "rustypaste"
                client_secret = "secret"
                [authorization]
                "#,
                config::FileFormat::Toml,
            ))
            .build()?
            .try_deserialize()?;
        assert_eq!(DEFAULT_AUTH_TIMEOUT, auth.session_idle_timeout);
        assert_eq!(DEFAULT_AUTH_TIMEOUT, auth.token_idle_timeout);
        assert!(auth.secure_cookies);
        Ok(())
    }

    #[test]
    fn auth_config_validates_https_and_service_token_sources() {
        let server = secure_server();
        let mut auth = valid_auth();
        assert!(auth.validate(&server).is_ok());

        auth.oidc.issuer_url = String::from("http://identity.example.com");
        assert!(auth.validate(&server).is_err());
        auth.allow_insecure_http = true;
        assert!(auth.validate(&server).is_ok());

        let mut local_server = server;
        local_server.url = Some(String::from("http://127.0.0.1:8000"));
        assert!(auth.validate(&local_server).is_err());
        auth.secure_cookies = false;
        assert!(auth.validate(&local_server).is_ok());

        local_server.upload_path = PathBuf::from("./upload");
        auth.database_path = PathBuf::from("./upload/auth.sqlite3");
        assert!(auth.validate(&local_server).is_err());
        auth.database_path = PathBuf::from("./auth.sqlite3");

        auth.service_accounts.insert(
            String::from("uploader"),
            ServiceAccountConfig {
                token: Some(SecretString::new("inline")),
                token_env: Some(String::from("UPLOAD_TOKEN")),
                ..ServiceAccountConfig::default()
            },
        );
        assert!(auth.validate(&local_server).is_err());
    }

    #[test]
    fn auth_urls_reject_credentials_queries_and_fragments() {
        let mut auth = valid_auth();
        let mut server = secure_server();

        server.url = Some(String::from("https://user:secret@paste.example.com"));
        assert!(auth.validate(&server).is_err());

        server = secure_server();
        server.url = Some(String::from("https://paste.example.com/root?tenant=one"));
        assert!(auth.validate(&server).is_err());

        server = secure_server();
        auth.oidc.issuer_url = String::from("https://identity.example.com/#metadata");
        assert!(auth.validate(&server).is_err());
    }

    #[test]
    fn claim_rules_match_all_keys_and_any_scalar_or_array_value() {
        let rules = ClaimRules::new(BTreeMap::from([
            (
                String::from("tenant"),
                ClaimValues::One(String::from("engineering")),
            ),
            (
                String::from("groups"),
                ClaimValues::Any(vec![String::from("paste-users"), String::from("admins")]),
            ),
        ]));
        let claims = json!({
            "tenant": "engineering",
            "groups": ["readers", "paste-users"]
        });
        assert!(rules.matches(claims.as_object().expect("object claims")));

        let wrong_tenant = json!({
            "tenant": "finance",
            "groups": "admins"
        });
        assert!(!rules.matches(wrong_tenant.as_object().expect("object claims")));
    }

    #[test]
    fn empty_admin_rules_do_not_grant_admin() {
        let authorization = AuthorizationConfig::default();
        let claims = JsonMap::new();
        assert!(authorization.allows(&claims));
        assert!(!authorization.is_admin(&claims));
    }

    #[test]
    fn debug_output_redacts_all_inline_secrets() {
        let mut auth = valid_auth();
        auth.service_accounts.insert(
            String::from("uploader"),
            ServiceAccountConfig {
                token: Some(SecretString::new("service-secret")),
                ..ServiceAccountConfig::default()
            },
        );
        let debug = format!("{auth:?}");
        assert!(!debug.contains("oidc-secret"));
        assert!(!debug.contains("service-secret"));
        assert!(debug.contains("[REDACTED]"));
    }
}
