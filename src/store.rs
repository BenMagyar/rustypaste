//! SQLite persistence for identities, credentials, login flows, and paste ownership.

use crate::config::{AuthConfig, SecretString};
use crate::paste::PasteType;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const MIGRATION_1: &str = include_str!("../migrations/0001_auth_and_ownership.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_public_link_reservations.sql");
const ROLLING_UPDATE_INTERVAL_SECONDS: i64 = 60 * 60;
// Bound dynamically issued per-principal credentials while allowing normal multi-device use.
const MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL: i64 = 32;
const MAX_ACTIVE_OAUTH_FLOWS: i64 = 10_000;
const MAX_ACTIVE_DEVICE_FLOWS: i64 = 10_000;

/// Persistence errors.
#[derive(Debug)]
pub enum StoreError {
    /// A SQLite operation failed.
    Database(sqlx::Error),
    /// A filesystem operation needed to open the database failed.
    Io(std::io::Error),
    /// The system clock is earlier than the Unix epoch.
    InvalidSystemTime,
    /// Cryptographic random generation failed.
    RandomGeneration,
    /// A persisted enum value was not recognized.
    InvalidData(String),
    /// A caller supplied a value that cannot be persisted safely.
    InvalidInput(String),
    /// A bounded transient-flow table has reached its active admission limit.
    CapacityExceeded(String),
    /// An active paste already owns the requested public filename.
    PublicFilenameConflict(String),
    /// A duration cannot be represented by the SQLite schema.
    DurationOverflow,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidSystemTime => {
                formatter.write_str("system clock is earlier than Unix epoch")
            }
            Self::RandomGeneration => formatter.write_str("secure random generation failed"),
            Self::InvalidData(message) => write!(formatter, "invalid persisted data: {message}"),
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::CapacityExceeded(message) => write!(formatter, "capacity exceeded: {message}"),
            Self::PublicFilenameConflict(filename) => {
                write!(formatter, "public filename is already in use: {filename}")
            }
            Self::DurationOverflow => formatter.write_str("duration is too large to persist"),
        }
    }
}

impl StdError for StoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The stable kind of a principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    /// A human identity identified by its OIDC issuer and subject.
    Oidc,
    /// A named service account.
    Service,
    /// The shared principal for deprecated static auth tokens.
    Legacy,
}

impl PrincipalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Service => "service",
            Self::Legacy => "legacy",
        }
    }

    fn from_str(value: &str) -> Result<Self, StoreError> {
        match value {
            "oidc" => Ok(Self::Oidc),
            "service" => Ok(Self::Service),
            "legacy" => Ok(Self::Legacy),
            value => Err(StoreError::InvalidData(format!(
                "unknown principal kind {value:?}"
            ))),
        }
    }
}

/// A persisted authenticated identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Database identifier.
    pub id: i64,
    /// Stable identity kind.
    pub kind: PrincipalKind,
    /// OIDC issuer for human identities.
    pub issuer: Option<String>,
    /// OIDC subject for human identities.
    pub subject: Option<String>,
    /// Stable configured name for service and legacy identities.
    pub stable_name: Option<String>,
    /// Informational email from the latest login.
    pub email: Option<String>,
    /// Informational display name from the latest login.
    pub display_name: Option<String>,
    /// Whether the identity currently has administrator access.
    pub is_admin: bool,
    /// Whether the identity may delete any paste without other admin privileges.
    pub can_delete_all: bool,
    /// Creation time as Unix seconds.
    pub created_at: i64,
    /// Most recent authenticated activity as Unix seconds.
    pub last_seen_at: i64,
}

/// A newly generated opaque credential.
#[derive(Clone, Debug)]
pub struct IssuedCredential {
    /// Database identifier for administrative revocation.
    pub id: i64,
    /// Plaintext credential. It is never persisted and its debug form is redacted.
    pub secret: SecretString,
    /// Idle expiry as Unix seconds.
    pub expires_at: i64,
}

/// The principal resolved from a valid session or API token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    /// Credential database identifier.
    pub credential_id: i64,
    /// Credential expiry after any rolling extension.
    pub expires_at: i64,
    /// Authenticated identity.
    pub principal: Principal,
}

/// A consumed OAuth transaction.
#[derive(Clone, Debug)]
pub struct OAuthFlow {
    /// PKCE code verifier.
    pub code_verifier: SecretString,
    /// Expected OIDC nonce.
    pub nonce: SecretString,
    /// Validated relative URL to restore after login.
    pub return_to: String,
}

/// A newly started CLI browser-assisted login.
#[derive(Clone, Debug)]
pub struct DeviceAuthorization {
    /// Opaque code used only by the polling CLI.
    pub device_code: SecretString,
    /// Short code displayed to the browser user.
    pub user_code: String,
    /// Human-readable client name shown during browser approval.
    pub client_name: String,
    /// Expiry as Unix seconds.
    pub expires_at: i64,
    /// Minimum polling interval.
    pub poll_interval: Duration,
}

/// Result of polling a CLI device authorization.
#[derive(Clone, Debug)]
pub enum DevicePoll {
    /// The browser has not approved the request yet.
    Pending,
    /// The caller polled sooner than the advertised interval.
    SlowDown,
    /// The request expired or the device code was invalid.
    Expired,
    /// The credential was already returned by an earlier poll.
    Consumed,
    /// The request was approved and this is the single credential delivery.
    Authorized {
        /// Authenticated identity that approved the request.
        principal: Principal,
        /// Newly issued CLI/API token.
        credential: IssuedCredential,
    },
}

/// Result of an opt-in, concurrency-safe deduplicating paste insert.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasteInsert {
    /// New metadata was inserted for the uploaded file.
    Inserted(PasteRecord),
    /// An existing compatible paste owned by the same principal won the race.
    Duplicate(PasteRecord),
}

/// Paste metadata to insert or reconcile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewPaste {
    /// Owner, or `None` for reconciled legacy content.
    pub owner_principal_id: Option<i64>,
    /// Filename exposed in the paste URL.
    pub public_filename: String,
    /// Exact on-disk storage path.
    pub storage_path: PathBuf,
    /// Paste storage behavior.
    pub paste_type: PasteType,
    /// Creation time as Unix seconds.
    pub created_at: i64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Optional expiry as Unix seconds.
    pub expires_at: Option<i64>,
    /// Hex or base64 content digest supplied by the paste layer.
    pub content_hash: String,
}

/// Persisted paste metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasteRecord {
    /// Database identifier.
    pub id: i64,
    /// Owner, or `None` for legacy content.
    pub owner_principal_id: Option<i64>,
    /// Filename exposed in the paste URL.
    pub public_filename: String,
    /// Exact on-disk storage path.
    pub storage_path: PathBuf,
    /// Paste storage behavior.
    pub paste_type: PasteType,
    /// Creation time as Unix seconds.
    pub created_at: i64,
    /// Most recent metadata update as Unix seconds.
    pub updated_at: i64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Optional expiry as Unix seconds.
    pub expires_at: Option<i64>,
    /// Content digest supplied by the paste layer.
    pub content_hash: String,
}

/// Result of reconciling a complete filesystem scan with paste metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileResult {
    /// Previously untracked filesystem entries inserted as legacy pastes.
    pub inserted: u64,
    /// Database entries removed because their files no longer exist.
    pub removed: u64,
}

/// Cloneable SQLite-backed authentication and ownership store.
#[derive(Clone, Debug)]
pub struct AuthStore {
    pool: SqlitePool,
    session_idle_timeout: Duration,
    token_idle_timeout: Duration,
}

impl AuthStore {
    /// Opens the configured SQLite database, enables WAL mode, and applies migrations.
    pub async fn connect(config: &AuthConfig) -> Result<Self, StoreError> {
        Self::open(
            &config.database_path,
            config.session_idle_timeout,
            config.token_idle_timeout,
        )
        .await
    }

    /// Opens a SQLite database with explicit rolling credential timeouts.
    pub async fn open(
        path: &Path,
        session_idle_timeout: Duration,
        token_idle_timeout: Duration,
    ) -> Result<Self, StoreError> {
        duration_seconds(session_idle_timeout)?;
        duration_seconds(token_idle_timeout)?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let database_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            database_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        apply_migrations(&pool).await?;

        Ok(Self {
            pool,
            session_idle_timeout,
            token_idle_timeout,
        })
    }

    /// Closes all pooled SQLite connections.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Inserts or refreshes an OIDC principal identified only by `(issuer, subject)`.
    pub async fn upsert_oidc_principal(
        &self,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        is_admin: bool,
    ) -> Result<Principal, StoreError> {
        if issuer.trim().is_empty() || subject.trim().is_empty() {
            return Err(StoreError::InvalidInput(String::from(
                "OIDC issuer and subject cannot be empty",
            )));
        }
        let now = unix_now()?;
        let row = sqlx::query(
            "INSERT INTO principals \
             (kind, issuer, subject, email, display_name, is_admin, can_delete_all, \
              created_at, updated_at, last_seen_at) \
             VALUES ('oidc', ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT DO UPDATE SET \
                 email = excluded.email, \
                 display_name = excluded.display_name, \
                 is_admin = excluded.is_admin, \
                 can_delete_all = excluded.can_delete_all, \
                 updated_at = excluded.updated_at, \
                 last_seen_at = excluded.last_seen_at \
             RETURNING id, kind, issuer, subject, stable_name, email, display_name, \
                       is_admin, can_delete_all, created_at, last_seen_at",
        )
        .bind(issuer)
        .bind(subject)
        .bind(email)
        .bind(display_name)
        .bind(is_admin)
        .bind(is_admin)
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        principal_from_row(&row)
    }

    /// Inserts or refreshes a named service principal.
    pub async fn upsert_service_principal(
        &self,
        stable_name: &str,
        is_admin: bool,
    ) -> Result<Principal, StoreError> {
        self.upsert_named_principal(PrincipalKind::Service, stable_name, is_admin, is_admin)
            .await
    }

    /// Inserts or refreshes a deprecated static-token principal.
    ///
    /// Legacy principals are never administrators. The boolean grants only the
    /// historical ability to delete any paste.
    pub async fn upsert_legacy_principal(
        &self,
        stable_name: &str,
        can_delete_all: bool,
    ) -> Result<Principal, StoreError> {
        self.upsert_named_principal(PrincipalKind::Legacy, stable_name, false, can_delete_all)
            .await
    }

    async fn upsert_named_principal(
        &self,
        kind: PrincipalKind,
        stable_name: &str,
        is_admin: bool,
        can_delete_all: bool,
    ) -> Result<Principal, StoreError> {
        if kind == PrincipalKind::Oidc || stable_name.trim().is_empty() {
            return Err(StoreError::InvalidInput(String::from(
                "named principal requires a non-empty service or legacy name",
            )));
        }
        let now = unix_now()?;
        let row = sqlx::query(
            "INSERT INTO principals \
             (kind, stable_name, is_admin, can_delete_all, created_at, updated_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT DO UPDATE SET \
                 is_admin = excluded.is_admin, \
                 can_delete_all = excluded.can_delete_all, \
                 updated_at = excluded.updated_at \
             RETURNING id, kind, issuer, subject, stable_name, email, display_name, \
                       is_admin, can_delete_all, created_at, last_seen_at",
        )
        .bind(kind.as_str())
        .bind(stable_name)
        .bind(is_admin)
        .bind(can_delete_all)
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        principal_from_row(&row)
    }

    /// Returns a principal by database identifier.
    pub async fn get_principal(&self, id: i64) -> Result<Option<Principal>, StoreError> {
        let row = sqlx::query(
            "SELECT id, kind, issuer, subject, stable_name, email, display_name, \
                    is_admin, can_delete_all, created_at, last_seen_at \
             FROM principals WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(principal_from_row).transpose()
    }

    /// Lists all principals for administrator inspection.
    pub async fn list_principals(&self) -> Result<Vec<Principal>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, kind, issuer, subject, stable_name, email, display_name, \
                    is_admin, can_delete_all, created_at, last_seen_at \
             FROM principals ORDER BY kind, COALESCE(stable_name, subject), id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(principal_from_row).collect()
    }

    /// Revokes all browser sessions and API tokens belonging to a principal.
    pub async fn revoke_principal_credentials(&self, principal_id: i64) -> Result<u64, StoreError> {
        let now = unix_now()?;
        let mut transaction = self.pool.begin().await?;
        let sessions = sqlx::query(
            "UPDATE browser_sessions SET revoked_at = ? \
             WHERE principal_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(principal_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let tokens = sqlx::query(
            "UPDATE api_tokens SET revoked_at = ? \
             WHERE principal_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(principal_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        transaction.commit().await?;
        Ok(sessions + tokens)
    }
}

async fn apply_migrations(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS rustypaste_schema_migrations (\
             version INTEGER PRIMARY KEY, \
             description TEXT NOT NULL, \
             applied_at INTEGER NOT NULL\
         )",
    )
    .execute(&mut *transaction)
    .await?;
    for (version, description, migration) in [
        (1_i64, "authentication and paste ownership", MIGRATION_1),
        (2_i64, "atomic public link reservations", MIGRATION_2),
    ] {
        let applied = sqlx::query("SELECT 1 FROM rustypaste_schema_migrations WHERE version = ?")
            .bind(version)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
        if !applied {
            sqlx::raw_sql(migration).execute(&mut *transaction).await?;
            sqlx::query(
                "INSERT INTO rustypaste_schema_migrations (version, description, applied_at) \
                 VALUES (?, ?, ?)",
            )
            .bind(version)
            .bind(description)
            .bind(unix_now()?)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

impl AuthStore {
    /// Creates a browser session and returns its plaintext cookie value once.
    pub async fn create_browser_session(
        &self,
        principal_id: i64,
    ) -> Result<IssuedCredential, StoreError> {
        create_credential(
            &self.pool,
            CredentialTable::BrowserSession,
            principal_id,
            None,
            self.session_idle_timeout,
        )
        .await
    }

    /// Creates a CLI/API bearer token and returns its plaintext value once.
    pub async fn create_api_token(
        &self,
        principal_id: i64,
        label: Option<&str>,
    ) -> Result<IssuedCredential, StoreError> {
        create_credential(
            &self.pool,
            CredentialTable::ApiToken,
            principal_id,
            label,
            self.token_idle_timeout,
        )
        .await
    }

    /// Revokes every API token managed by service-account or legacy configuration.
    ///
    /// Call this once during startup before provisioning the currently configured
    /// tokens. CLI-issued tokens use a different label and are left untouched.
    pub async fn revoke_managed_api_tokens(&self) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = ? \
             WHERE revoked_at IS NULL AND (\
                 label GLOB 'service:*' OR label IN ('legacy-auth', 'legacy-delete')\
             )",
        )
        .bind(unix_now()?)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Associates a configured static bearer token with a principal.
    ///
    /// Only its SHA-256 digest is persisted. Re-provisioning the same configured
    /// token extends its idle expiry and clears a prior revocation.
    pub async fn provision_static_api_token(
        &self,
        principal_id: i64,
        token: &SecretString,
        label: Option<&str>,
    ) -> Result<i64, StoreError> {
        if token.is_empty() {
            return Err(StoreError::InvalidInput(String::from(
                "static API token cannot be empty",
            )));
        }
        let hash = secret_hash(token.expose());
        let now = unix_now()?;
        let expires_at = expiry_from(now, self.token_idle_timeout)?;
        let mut transaction = self.pool.begin().await?;
        let existing = sqlx::query("SELECT id, principal_id FROM api_tokens WHERE secret_hash = ?")
            .bind(&hash)
            .fetch_optional(&mut *transaction)
            .await?;
        let id = if let Some(existing) = existing {
            let existing_principal_id: i64 = existing.try_get("principal_id")?;
            if existing_principal_id != principal_id {
                return Err(StoreError::InvalidInput(String::from(
                    "the same static token cannot belong to multiple principals",
                )));
            }
            let id: i64 = existing.try_get("id")?;
            sqlx::query(
                "UPDATE api_tokens SET label = ?, last_used_at = ?, expires_at = ?, revoked_at = NULL \
                 WHERE id = ?",
            )
            .bind(label)
            .bind(now)
            .bind(expires_at)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
            id
        } else {
            sqlx::query(
                "INSERT INTO api_tokens \
                 (principal_id, secret_hash, label, created_at, last_used_at, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            )
            .bind(principal_id)
            .bind(&hash)
            .bind(label)
            .bind(now)
            .bind(now)
            .bind(expires_at)
            .fetch_one(&mut *transaction)
            .await?
            .try_get("id")?
        };
        transaction.commit().await?;
        Ok(id)
    }

    /// Resolves a valid browser session and rolls its idle expiry at most hourly.
    pub async fn authenticate_browser_session(
        &self,
        secret: &str,
    ) -> Result<Option<AuthenticatedPrincipal>, StoreError> {
        authenticate_credential(
            &self.pool,
            CredentialTable::BrowserSession,
            secret,
            self.session_idle_timeout,
        )
        .await
    }

    /// Resolves a valid CLI/API token and rolls its idle expiry at most hourly.
    pub async fn authenticate_api_token(
        &self,
        secret: &str,
    ) -> Result<Option<AuthenticatedPrincipal>, StoreError> {
        authenticate_credential(
            &self.pool,
            CredentialTable::ApiToken,
            secret,
            self.token_idle_timeout,
        )
        .await
    }

    /// Revokes a browser session by its plaintext cookie value.
    pub async fn revoke_browser_session(&self, secret: &str) -> Result<bool, StoreError> {
        revoke_credential(&self.pool, CredentialTable::BrowserSession, secret).await
    }

    /// Revokes an API token by its plaintext bearer value.
    pub async fn revoke_api_token(&self, secret: &str) -> Result<bool, StoreError> {
        revoke_credential(&self.pool, CredentialTable::ApiToken, secret).await
    }

    /// Revokes an API token by database identifier.
    pub async fn revoke_api_token_by_id(&self, token_id: i64) -> Result<bool, StoreError> {
        let result =
            sqlx::query("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(unix_now()?)
                .bind(token_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Deletes revoked or expired credentials and expired transient login flows.
    pub async fn purge_expired(&self) -> Result<u64, StoreError> {
        let now = unix_now()?;
        let mut transaction = self.pool.begin().await?;
        let mut affected = 0;
        for statement in [
            "DELETE FROM browser_sessions WHERE revoked_at IS NOT NULL OR expires_at <= ?",
            "DELETE FROM api_tokens WHERE revoked_at IS NOT NULL OR expires_at <= ?",
        ] {
            affected += sqlx::query(statement)
                .bind(now)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        }
        for statement in [
            "DELETE FROM oauth_flows WHERE expires_at <= ?",
            "DELETE FROM cli_device_flows WHERE expires_at <= ?",
        ] {
            affected += sqlx::query(statement)
                .bind(now)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        }
        transaction.commit().await?;
        Ok(affected)
    }

    /// Persists an OIDC authorization transaction created by the OIDC client.
    ///
    /// OAuth state is stored only as a SHA-256 digest. `return_to` must be a
    /// same-origin relative path beginning with one slash.
    pub async fn store_oauth_flow(
        &self,
        state: &str,
        code_verifier: &str,
        nonce: &str,
        return_to: &str,
        lifetime: Duration,
    ) -> Result<i64, StoreError> {
        if state.is_empty() || code_verifier.is_empty() || nonce.is_empty() {
            return Err(StoreError::InvalidInput(String::from(
                "OAuth state, PKCE verifier, and nonce cannot be empty",
            )));
        }
        validate_return_to(return_to)?;
        let now = unix_now()?;
        let expires_at = expiry_from(now, lifetime)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM oauth_flows WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_flows")
            .fetch_one(&mut *transaction)
            .await?;
        if active >= MAX_ACTIVE_OAUTH_FLOWS {
            transaction.commit().await?;
            return Err(StoreError::CapacityExceeded(String::from(
                "too many active OAuth login flows; try again later",
            )));
        }
        sqlx::query(
            "INSERT INTO oauth_flows \
             (state_hash, code_verifier, nonce, return_to, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(secret_hash(state))
        .bind(code_verifier)
        .bind(nonce)
        .bind(return_to)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(expires_at)
    }

    /// Atomically consumes a valid OAuth transaction, preventing callback replay.
    pub async fn consume_oauth_flow(&self, state: &str) -> Result<Option<OAuthFlow>, StoreError> {
        if state.is_empty() {
            return Ok(None);
        }
        let row = sqlx::query(
            "DELETE FROM oauth_flows \
             WHERE state_hash = ? AND expires_at > ? \
             RETURNING code_verifier, nonce, return_to",
        )
        .bind(secret_hash(state))
        .bind(unix_now()?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(OAuthFlow {
                code_verifier: SecretString::new(row.try_get::<String, _>("code_verifier")?),
                nonce: SecretString::new(row.try_get::<String, _>("nonce")?),
                return_to: row.try_get("return_to")?,
            })
        })
        .transpose()
    }

    /// Starts a browser-assisted CLI login transaction.
    pub async fn start_device_flow(
        &self,
        client_name: &str,
        lifetime: Duration,
        poll_interval: Duration,
    ) -> Result<DeviceAuthorization, StoreError> {
        if client_name.trim().is_empty()
            || client_name.len() > 100
            || client_name.chars().any(char::is_control)
        {
            return Err(StoreError::InvalidInput(String::from(
                "device client name must be 1 to 100 non-control characters",
            )));
        }
        let poll_seconds = duration_seconds(poll_interval)?;
        if poll_seconds == 0 {
            return Err(StoreError::InvalidInput(String::from(
                "device polling interval must be greater than zero",
            )));
        }
        let now = unix_now()?;
        let expires_at = expiry_from(now, lifetime)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM cli_device_flows WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        let active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cli_device_flows WHERE delivered_at IS NULL")
                .fetch_one(&mut *transaction)
                .await?;
        if active >= MAX_ACTIVE_DEVICE_FLOWS {
            transaction.commit().await?;
            return Err(StoreError::CapacityExceeded(String::from(
                "too many active CLI login flows; try again later",
            )));
        }

        // A collision is cryptographically negligible, but retrying keeps the
        // uniqueness constraint from becoming an externally visible failure.
        for _ in 0..4 {
            let device_code = generate_secret()?;
            let user_code = generate_user_code()?;
            let result = sqlx::query(
                "INSERT INTO cli_device_flows \
                 (device_code_hash, user_code, client_name, created_at, expires_at, \
                  poll_interval_seconds) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(secret_hash(device_code.expose()))
            .bind(&user_code)
            .bind(client_name)
            .bind(now)
            .bind(expires_at)
            .bind(poll_seconds)
            .execute(&mut *transaction)
            .await;
            match result {
                Ok(_) => {
                    transaction.commit().await?;
                    return Ok(DeviceAuthorization {
                        device_code,
                        user_code,
                        client_name: client_name.to_string(),
                        expires_at,
                        poll_interval,
                    });
                }
                Err(sqlx::Error::Database(error)) if error.is_unique_violation() => continue,
                Err(error) => return Err(error.into()),
            }
        }
        transaction.commit().await?;
        Err(StoreError::RandomGeneration)
    }

    /// Returns the client name for an active device flow identified by user code.
    pub async fn get_device_flow_client_name(
        &self,
        user_code: &str,
    ) -> Result<Option<String>, StoreError> {
        let client_name = sqlx::query_scalar(
            "SELECT client_name FROM cli_device_flows \
             WHERE user_code = ? AND delivered_at IS NULL AND expires_at > ?",
        )
        .bind(normalize_user_code(user_code))
        .bind(unix_now()?)
        .fetch_optional(&self.pool)
        .await?;
        Ok(client_name)
    }

    /// Approves a pending CLI login using the browser-visible user code.
    pub async fn approve_device_flow(
        &self,
        user_code: &str,
        principal_id: i64,
    ) -> Result<bool, StoreError> {
        let now = unix_now()?;
        let result = sqlx::query(
            "UPDATE cli_device_flows \
             SET approved_principal_id = ?, approved_at = ? \
             WHERE user_code = ? AND approved_principal_id IS NULL \
               AND delivered_at IS NULL AND expires_at > ?",
        )
        .bind(principal_id)
        .bind(now)
        .bind(normalize_user_code(user_code))
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Polls a device flow and atomically delivers at most one API token.
    pub async fn poll_device_flow(
        &self,
        device_code: &str,
        token_label: Option<&str>,
    ) -> Result<DevicePoll, StoreError> {
        if device_code.is_empty() {
            return Ok(DevicePoll::Expired);
        }
        let now = unix_now()?;
        let hash = secret_hash(device_code);
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT id, approved_principal_id, expires_at, poll_interval_seconds, \
                    last_polled_at, delivered_at \
             FROM cli_device_flows WHERE device_code_hash = ?",
        )
        .bind(&hash)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(DevicePoll::Expired);
        };
        let flow_id: i64 = row.try_get("id")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        if expires_at <= now {
            sqlx::query("DELETE FROM cli_device_flows WHERE id = ?")
                .bind(flow_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(DevicePoll::Expired);
        }
        if row.try_get::<Option<i64>, _>("delivered_at")?.is_some() {
            transaction.commit().await?;
            return Ok(DevicePoll::Consumed);
        }
        let poll_interval: i64 = row.try_get("poll_interval_seconds")?;
        let last_polled_at: Option<i64> = row.try_get("last_polled_at")?;
        if last_polled_at.is_some_and(|last_poll| now < last_poll.saturating_add(poll_interval)) {
            sqlx::query("UPDATE cli_device_flows SET last_polled_at = ? WHERE id = ?")
                .bind(now)
                .bind(flow_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(DevicePoll::SlowDown);
        }
        sqlx::query("UPDATE cli_device_flows SET last_polled_at = ? WHERE id = ?")
            .bind(now)
            .bind(flow_id)
            .execute(&mut *transaction)
            .await?;
        let Some(principal_id) = row.try_get::<Option<i64>, _>("approved_principal_id")? else {
            transaction.commit().await?;
            return Ok(DevicePoll::Pending);
        };

        let claimed = sqlx::query(
            "UPDATE cli_device_flows SET delivered_at = ? \
             WHERE id = ? AND delivered_at IS NULL AND approved_principal_id IS NOT NULL",
        )
        .bind(now)
        .bind(flow_id)
        .execute(&mut *transaction)
        .await?;
        if claimed.rows_affected() != 1 {
            transaction.commit().await?;
            return Ok(DevicePoll::Consumed);
        }

        let principal = get_principal_in_transaction(&mut transaction, principal_id).await?;
        let secret = generate_secret()?;
        let token_expiry = expiry_from(now, self.token_idle_timeout)?;
        let token_id: i64 = sqlx::query(
            "INSERT INTO api_tokens \
             (principal_id, secret_hash, label, created_at, last_used_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(principal_id)
        .bind(secret_hash(secret.expose()))
        .bind(token_label)
        .bind(now)
        .bind(now)
        .bind(token_expiry)
        .fetch_one(&mut *transaction)
        .await?
        .try_get("id")?;
        prune_credentials(
            &mut transaction,
            CredentialTable::ApiToken,
            principal_id,
            now,
        )
        .await?;
        transaction.commit().await?;

        Ok(DevicePoll::Authorized {
            principal,
            credential: IssuedCredential {
                id: token_id,
                secret,
                expires_at: token_expiry,
            },
        })
    }

    /// Inserts metadata for a newly stored paste.
    pub async fn insert_paste(&self, paste: &NewPaste) -> Result<PasteRecord, StoreError> {
        validate_new_paste(paste)?;
        let now = unix_now()?;
        let link_key = active_public_link_key(paste, now);
        let storage_path = path_to_string(&paste.storage_path)?;
        let size_bytes =
            i64::try_from(paste.size_bytes).map_err(|_| StoreError::DurationOverflow)?;
        let mut transaction = self.pool.begin().await?;
        if let Some(link_key) = link_key {
            prepare_public_link(&mut transaction, link_key, now).await?;
        }
        let insert = sqlx::query(
            "INSERT INTO pastes \
             (owner_principal_id, public_filename, storage_path, paste_type, created_at, \
              updated_at, size_bytes, expires_at, content_hash, link_key) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             RETURNING id, owner_principal_id, public_filename, storage_path, paste_type, \
                       created_at, updated_at, size_bytes, expires_at, content_hash",
        )
        .bind(paste.owner_principal_id)
        .bind(&paste.public_filename)
        .bind(storage_path)
        .bind(paste_type_to_str(paste.paste_type))
        .bind(paste.created_at)
        .bind(paste.created_at)
        .bind(size_bytes)
        .bind(paste.expires_at)
        .bind(&paste.content_hash)
        .bind(link_key)
        .fetch_one(&mut *transaction)
        .await;
        match (insert, link_key) {
            (Ok(row), _) => {
                let record = paste_from_row(&row)?;
                transaction.commit().await?;
                Ok(record)
            }
            (Err(error), Some(link_key)) if is_unique_violation(&error) => {
                if public_link_is_active(&mut transaction, link_key, now).await? {
                    Err(StoreError::PublicFilenameConflict(link_key.to_string()))
                } else {
                    Err(StoreError::Database(error))
                }
            }
            (Err(error), _) => Err(error.into()),
        }
    }

    /// Atomically inserts metadata or returns an existing compatible owner duplicate.
    ///
    /// This opt-in path is only for non-expiring file, remote-file, and URL
    /// pastes when duplicate suppression is configured. Ordinary inserts leave
    /// the deduplication key null and remain unrestricted.
    pub async fn insert_paste_deduplicated(
        &self,
        paste: &NewPaste,
    ) -> Result<PasteInsert, StoreError> {
        validate_new_paste(paste)?;
        let owner_principal_id = paste.owner_principal_id.ok_or_else(|| {
            StoreError::InvalidInput(String::from("deduplicated paste inserts require an owner"))
        })?;
        if paste.expires_at.is_some() {
            return Err(StoreError::InvalidInput(String::from(
                "expiring pastes cannot use persistent deduplication",
            )));
        }
        let category = dedup_category(paste.paste_type).ok_or_else(|| {
            StoreError::InvalidInput(String::from(
                "this paste type does not support duplicate suppression",
            ))
        })?;
        let dedup_key = format!("{category}:{}", paste.content_hash);
        let now = unix_now()?;
        let link_key = &paste.public_filename;
        let storage_path = path_to_string(&paste.storage_path)?;
        let size_bytes =
            i64::try_from(paste.size_bytes).map_err(|_| StoreError::DurationOverflow)?;
        let mut transaction = self.pool.begin().await?;
        clear_expired_public_link(&mut transaction, link_key, now).await?;

        if let Some(existing) =
            find_dedup_in_transaction(&mut transaction, owner_principal_id, &dedup_key).await?
        {
            transaction.commit().await?;
            return Ok(PasteInsert::Duplicate(existing));
        }
        ensure_public_link_available(&mut transaction, link_key, now).await?;

        let insert = sqlx::query(
            "INSERT INTO pastes \
             (owner_principal_id, public_filename, storage_path, paste_type, created_at, \
              updated_at, size_bytes, expires_at, content_hash, dedup_key, link_key) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             RETURNING id, owner_principal_id, public_filename, storage_path, paste_type, \
                       created_at, updated_at, size_bytes, expires_at, content_hash",
        )
        .bind(owner_principal_id)
        .bind(&paste.public_filename)
        .bind(storage_path)
        .bind(paste_type_to_str(paste.paste_type))
        .bind(paste.created_at)
        .bind(paste.created_at)
        .bind(size_bytes)
        .bind(paste.expires_at)
        .bind(&paste.content_hash)
        .bind(&dedup_key)
        .bind(link_key)
        .fetch_one(&mut *transaction)
        .await;

        match insert {
            Ok(row) => {
                let record = paste_from_row(&row)?;
                transaction.commit().await?;
                Ok(PasteInsert::Inserted(record))
            }
            Err(error) if is_unique_violation(&error) => {
                if let Some(existing) =
                    find_dedup_in_transaction(&mut transaction, owner_principal_id, &dedup_key)
                        .await?
                {
                    transaction.commit().await?;
                    Ok(PasteInsert::Duplicate(existing))
                } else if public_link_is_active(&mut transaction, link_key, now).await? {
                    Err(StoreError::PublicFilenameConflict(link_key.clone()))
                } else {
                    Err(StoreError::Database(error))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Returns paste metadata by database identifier.
    pub async fn get_paste(&self, id: i64) -> Result<Option<PasteRecord>, StoreError> {
        let statement = paste_select("WHERE id = ?");
        let row = sqlx::query(&statement)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(paste_from_row).transpose()
    }

    /// Returns paste metadata for an exact storage path.
    pub async fn find_paste_by_storage_path(
        &self,
        path: &Path,
    ) -> Result<Option<PasteRecord>, StoreError> {
        let statement = paste_select("WHERE storage_path = ?");
        let row = sqlx::query(&statement)
            .bind(path_to_string(path)?)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(paste_from_row).transpose()
    }

    /// Returns non-expired records matching an exact public paste filename.
    pub async fn find_pastes_by_public_filename(
        &self,
        filename: &str,
    ) -> Result<Vec<PasteRecord>, StoreError> {
        let statement = paste_select(
            "WHERE public_filename = ? AND (expires_at IS NULL OR expires_at > ?) \
             ORDER BY CASE paste_type \
                 WHEN 'file' THEN 0 WHEN 'remote_file' THEN 1 WHEN 'url' THEN 2 \
                 WHEN 'oneshot' THEN 3 WHEN 'oneshot_url' THEN 4 ELSE 5 END, id",
        );
        let rows = sqlx::query(&statement)
            .bind(filename)
            .bind(unix_now()?)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(paste_from_row).collect()
    }

    /// Finds non-expired duplicate content belonging to the same owner.
    pub async fn find_owner_duplicate(
        &self,
        owner_principal_id: i64,
        content_hash: &str,
    ) -> Result<Option<PasteRecord>, StoreError> {
        let statement = paste_select(
            "WHERE owner_principal_id = ? AND content_hash = ? \
             AND (expires_at IS NULL OR expires_at > ?) \
             ORDER BY created_at DESC LIMIT 1",
        );
        let row = sqlx::query(&statement)
            .bind(owner_principal_id)
            .bind(content_hash)
            .bind(unix_now()?)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(paste_from_row).transpose()
    }

    /// Lists a principal's non-expired pastes, newest first.
    pub async fn list_owner_pastes(
        &self,
        owner_principal_id: i64,
    ) -> Result<Vec<PasteRecord>, StoreError> {
        let statement = paste_select(
            "WHERE owner_principal_id = ? AND (expires_at IS NULL OR expires_at > ?) \
             ORDER BY created_at DESC, id DESC",
        );
        let rows = sqlx::query(&statement)
            .bind(owner_principal_id)
            .bind(unix_now()?)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(paste_from_row).collect()
    }

    /// Lists every non-expired paste for an explicit administrator scope.
    pub async fn list_all_pastes(&self) -> Result<Vec<PasteRecord>, StoreError> {
        let statement = paste_select(
            "WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC, id DESC",
        );
        let rows = sqlx::query(&statement)
            .bind(unix_now()?)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(paste_from_row).collect()
    }

    /// Deletes paste metadata by identifier and returns the removed record.
    pub async fn delete_paste(&self, id: i64) -> Result<Option<PasteRecord>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM pastes WHERE id = ? \
             RETURNING id, owner_principal_id, public_filename, storage_path, paste_type, \
                       created_at, updated_at, size_bytes, expires_at, content_hash",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(paste_from_row).transpose()
    }

    /// Deletes paste metadata by exact storage path and returns the removed record.
    pub async fn delete_paste_by_storage_path(
        &self,
        path: &Path,
    ) -> Result<Option<PasteRecord>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM pastes WHERE storage_path = ? \
             RETURNING id, owner_principal_id, public_filename, storage_path, paste_type, \
                       created_at, updated_at, size_bytes, expires_at, content_hash",
        )
        .bind(path_to_string(path)?)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(paste_from_row).transpose()
    }

    /// Reconciles a complete filesystem scan with the metadata database.
    ///
    /// Existing ownership is preserved. Newly discovered entries use the owner
    /// supplied by the caller (normally `None` for legacy content), and database
    /// entries absent from the complete scan are removed.
    pub async fn reconcile_pastes(
        &self,
        filesystem_pastes: &[NewPaste],
    ) -> Result<ReconcileResult, StoreError> {
        for paste in filesystem_pastes {
            validate_new_paste(paste)?;
        }
        let incoming_paths: HashSet<String> = filesystem_pastes
            .iter()
            .map(|paste| path_to_string(&paste.storage_path).map(str::to_string))
            .collect::<Result<_, _>>()?;
        let now = unix_now()?;
        let mut transaction = self.pool.begin().await?;
        let existing_paths = sqlx::query("SELECT storage_path FROM pastes")
            .fetch_all(&mut *transaction)
            .await?;
        let mut result = ReconcileResult::default();
        for row in existing_paths {
            let storage_path: String = row.try_get("storage_path")?;
            if !incoming_paths.contains(&storage_path) {
                result.removed += sqlx::query("DELETE FROM pastes WHERE storage_path = ?")
                    .bind(storage_path)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
            }
        }

        for paste in filesystem_pastes {
            let size_bytes = i64::try_from(paste.size_bytes)
                .map_err(|_| StoreError::InvalidInput(String::from("paste size is too large")))?;
            let inserted = sqlx::query(
                "INSERT INTO pastes \
                 (owner_principal_id, public_filename, storage_path, paste_type, created_at, \
                  updated_at, size_bytes, expires_at, content_hash) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(storage_path) DO NOTHING",
            )
            .bind(paste.owner_principal_id)
            .bind(&paste.public_filename)
            .bind(path_to_string(&paste.storage_path)?)
            .bind(paste_type_to_str(paste.paste_type))
            .bind(paste.created_at)
            .bind(now)
            .bind(size_bytes)
            .bind(paste.expires_at)
            .bind(&paste.content_hash)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            result.inserted += inserted;
            if inserted == 0 {
                sqlx::query(
                    "UPDATE pastes SET public_filename = ?, paste_type = ?, updated_at = ?, \
                     size_bytes = ?, expires_at = ?, content_hash = ? WHERE storage_path = ?",
                )
                .bind(&paste.public_filename)
                .bind(paste_type_to_str(paste.paste_type))
                .bind(now)
                .bind(size_bytes)
                .bind(paste.expires_at)
                .bind(&paste.content_hash)
                .bind(path_to_string(&paste.storage_path)?)
                .execute(&mut *transaction)
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(result)
    }
}

#[derive(Clone, Copy)]
enum CredentialTable {
    BrowserSession,
    ApiToken,
}

impl CredentialTable {
    fn insert_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "INSERT INTO browser_sessions \
                 (principal_id, secret_hash, created_at, last_used_at, expires_at) \
                 VALUES (?, ?, ?, ?, ?) RETURNING id"
            }
            Self::ApiToken => {
                "INSERT INTO api_tokens \
                 (principal_id, secret_hash, label, created_at, last_used_at, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id"
            }
        }
    }

    fn authenticate_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "SELECT c.id AS credential_id, c.last_used_at AS credential_last_used_at, \
                        c.expires_at AS credential_expires_at, \
                        p.id AS principal_id, p.kind AS principal_kind, p.issuer AS principal_issuer, \
                        p.subject AS principal_subject, p.stable_name AS principal_stable_name, \
                        p.email AS principal_email, p.display_name AS principal_display_name, \
                        p.is_admin AS principal_is_admin, \
                        p.can_delete_all AS principal_can_delete_all, \
                        p.created_at AS principal_created_at, \
                        p.last_seen_at AS principal_last_seen_at \
                 FROM browser_sessions c JOIN principals p ON p.id = c.principal_id \
                 WHERE c.secret_hash = ? AND c.revoked_at IS NULL"
            }
            Self::ApiToken => {
                "SELECT c.id AS credential_id, c.last_used_at AS credential_last_used_at, \
                        c.expires_at AS credential_expires_at, \
                        p.id AS principal_id, p.kind AS principal_kind, p.issuer AS principal_issuer, \
                        p.subject AS principal_subject, p.stable_name AS principal_stable_name, \
                        p.email AS principal_email, p.display_name AS principal_display_name, \
                        p.is_admin AS principal_is_admin, \
                        p.can_delete_all AS principal_can_delete_all, \
                        p.created_at AS principal_created_at, \
                        p.last_seen_at AS principal_last_seen_at \
                 FROM api_tokens c JOIN principals p ON p.id = c.principal_id \
                 WHERE c.secret_hash = ? AND c.revoked_at IS NULL"
            }
        }
    }

    fn roll_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "UPDATE browser_sessions SET last_used_at = ?, expires_at = ? \
                 WHERE id = ? AND last_used_at <= ? AND revoked_at IS NULL"
            }
            Self::ApiToken => {
                "UPDATE api_tokens SET last_used_at = ?, expires_at = ? \
                 WHERE id = ? AND last_used_at <= ? AND revoked_at IS NULL"
            }
        }
    }

    fn expire_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "UPDATE browser_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
            }
            Self::ApiToken => {
                "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
            }
        }
    }

    fn revoke_by_hash_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "UPDATE browser_sessions SET revoked_at = ? \
                 WHERE secret_hash = ? AND revoked_at IS NULL"
            }
            Self::ApiToken => {
                "UPDATE api_tokens SET revoked_at = ? \
                 WHERE secret_hash = ? AND revoked_at IS NULL"
            }
        }
    }

    fn prune_sql(self) -> &'static str {
        match self {
            Self::BrowserSession => {
                "DELETE FROM browser_sessions \
                 WHERE principal_id = ? AND (revoked_at IS NOT NULL OR expires_at <= ? OR \
                       id NOT IN (\
                           SELECT id FROM browser_sessions \
                           WHERE principal_id = ? AND revoked_at IS NULL AND expires_at > ? \
                           ORDER BY created_at DESC, id DESC LIMIT ?\
                       ))"
            }
            Self::ApiToken => {
                "DELETE FROM api_tokens \
                 WHERE principal_id = ? AND (revoked_at IS NOT NULL OR expires_at <= ? OR \
                       ((label IS NULL OR (label NOT GLOB 'service:*' AND \
                                          label NOT IN ('legacy-auth', 'legacy-delete'))) AND \
                        id NOT IN (\
                           SELECT id FROM api_tokens \
                           WHERE principal_id = ? AND revoked_at IS NULL AND expires_at > ? AND \
                                 (label IS NULL OR (label NOT GLOB 'service:*' AND \
                                                    label NOT IN ('legacy-auth', 'legacy-delete'))) \
                           ORDER BY created_at DESC, id DESC LIMIT ?\
                       )))"
            }
        }
    }
}

async fn create_credential(
    pool: &SqlitePool,
    table: CredentialTable,
    principal_id: i64,
    label: Option<&str>,
    timeout: Duration,
) -> Result<IssuedCredential, StoreError> {
    let secret = generate_secret()?;
    let hash = secret_hash(secret.expose());
    let now = unix_now()?;
    let expires_at = expiry_from(now, timeout)?;
    let mut transaction = pool.begin().await?;
    let mut query = sqlx::query(table.insert_sql())
        .bind(principal_id)
        .bind(hash);
    if matches!(table, CredentialTable::ApiToken) {
        query = query.bind(label);
    }
    let row = query
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .fetch_one(&mut *transaction)
        .await?;
    let credential = IssuedCredential {
        id: row.try_get("id")?,
        secret,
        expires_at,
    };
    prune_credentials(&mut transaction, table, principal_id, now).await?;
    transaction.commit().await?;
    Ok(credential)
}

async fn prune_credentials(
    transaction: &mut Transaction<'_, Sqlite>,
    table: CredentialTable,
    principal_id: i64,
    now: i64,
) -> Result<u64, StoreError> {
    let result = sqlx::query(table.prune_sql())
        .bind(principal_id)
        .bind(now)
        .bind(principal_id)
        .bind(now)
        .bind(MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL)
        .execute(&mut **transaction)
        .await?;
    Ok(result.rows_affected())
}

async fn authenticate_credential(
    pool: &SqlitePool,
    table: CredentialTable,
    secret: &str,
    timeout: Duration,
) -> Result<Option<AuthenticatedPrincipal>, StoreError> {
    if secret.is_empty() {
        return Ok(None);
    }
    let hash = secret_hash(secret);
    let Some(row) = sqlx::query(table.authenticate_sql())
        .bind(hash)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let credential_id: i64 = row.try_get("credential_id")?;
    let expires_at: i64 = row.try_get("credential_expires_at")?;
    let last_used_at: i64 = row.try_get("credential_last_used_at")?;
    let now = unix_now()?;
    if expires_at <= now {
        sqlx::query(table.expire_sql())
            .bind(now)
            .bind(credential_id)
            .execute(pool)
            .await?;
        return Ok(None);
    }

    let mut effective_expiry = expires_at;
    if last_used_at <= now.saturating_sub(ROLLING_UPDATE_INTERVAL_SECONDS) {
        let rolled_expiry = expiry_from(now, timeout)?;
        let result = sqlx::query(table.roll_sql())
            .bind(now)
            .bind(rolled_expiry)
            .bind(credential_id)
            .bind(now.saturating_sub(ROLLING_UPDATE_INTERVAL_SECONDS))
            .execute(pool)
            .await?;
        if result.rows_affected() == 1 {
            effective_expiry = rolled_expiry;
            sqlx::query("UPDATE principals SET last_seen_at = ?, updated_at = ? WHERE id = ?")
                .bind(now)
                .bind(now)
                .bind(row.try_get::<i64, _>("principal_id")?)
                .execute(pool)
                .await?;
        }
    }

    Ok(Some(AuthenticatedPrincipal {
        credential_id,
        expires_at: effective_expiry,
        principal: principal_from_auth_row(&row)?,
    }))
}

async fn revoke_credential(
    pool: &SqlitePool,
    table: CredentialTable,
    secret: &str,
) -> Result<bool, StoreError> {
    if secret.is_empty() {
        return Ok(false);
    }
    let result = sqlx::query(table.revoke_by_hash_sql())
        .bind(unix_now()?)
        .bind(secret_hash(secret))
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

fn principal_from_row(row: &SqliteRow) -> Result<Principal, StoreError> {
    Ok(Principal {
        id: row.try_get("id")?,
        kind: PrincipalKind::from_str(row.try_get("kind")?)?,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
        stable_name: row.try_get("stable_name")?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        is_admin: row.try_get("is_admin")?,
        can_delete_all: row.try_get("can_delete_all")?,
        created_at: row.try_get("created_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}

fn principal_from_auth_row(row: &SqliteRow) -> Result<Principal, StoreError> {
    Ok(Principal {
        id: row.try_get("principal_id")?,
        kind: PrincipalKind::from_str(row.try_get("principal_kind")?)?,
        issuer: row.try_get("principal_issuer")?,
        subject: row.try_get("principal_subject")?,
        stable_name: row.try_get("principal_stable_name")?,
        email: row.try_get("principal_email")?,
        display_name: row.try_get("principal_display_name")?,
        is_admin: row.try_get("principal_is_admin")?,
        can_delete_all: row.try_get("principal_can_delete_all")?,
        created_at: row.try_get("principal_created_at")?,
        last_seen_at: row.try_get("principal_last_seen_at")?,
    })
}

async fn get_principal_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    principal_id: i64,
) -> Result<Principal, StoreError> {
    let row = sqlx::query(
        "SELECT id, kind, issuer, subject, stable_name, email, display_name, \
                is_admin, can_delete_all, created_at, last_seen_at FROM principals WHERE id = ?",
    )
    .bind(principal_id)
    .fetch_one(&mut **transaction)
    .await?;
    principal_from_row(&row)
}

fn paste_from_row(row: &SqliteRow) -> Result<PasteRecord, StoreError> {
    let size_bytes: i64 = row.try_get("size_bytes")?;
    Ok(PasteRecord {
        id: row.try_get("id")?,
        owner_principal_id: row.try_get("owner_principal_id")?,
        public_filename: row.try_get("public_filename")?,
        storage_path: PathBuf::from(row.try_get::<String, _>("storage_path")?),
        paste_type: paste_type_from_str(row.try_get("paste_type")?)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        size_bytes: u64::try_from(size_bytes)
            .map_err(|_| StoreError::InvalidData(format!("negative paste size {size_bytes}")))?,
        expires_at: row.try_get("expires_at")?,
        content_hash: row.try_get("content_hash")?,
    })
}

fn paste_select(suffix: &str) -> String {
    format!(
        "SELECT id, owner_principal_id, public_filename, storage_path, paste_type, \
         created_at, updated_at, size_bytes, expires_at, content_hash FROM pastes {suffix}"
    )
}

fn paste_type_to_str(paste_type: PasteType) -> &'static str {
    match paste_type {
        PasteType::File => "file",
        PasteType::RemoteFile => "remote_file",
        PasteType::Oneshot => "oneshot",
        PasteType::Url => "url",
        PasteType::OneshotUrl => "oneshot_url",
        PasteType::ProtectedFile => "protected_file",
    }
}

fn paste_type_from_str(value: &str) -> Result<PasteType, StoreError> {
    match value {
        "file" => Ok(PasteType::File),
        "remote_file" => Ok(PasteType::RemoteFile),
        "oneshot" => Ok(PasteType::Oneshot),
        "url" => Ok(PasteType::Url),
        "oneshot_url" => Ok(PasteType::OneshotUrl),
        "protected_file" => Ok(PasteType::ProtectedFile),
        value => Err(StoreError::InvalidData(format!(
            "unknown paste type {value:?}"
        ))),
    }
}

fn dedup_category(paste_type: PasteType) -> Option<&'static str> {
    match paste_type {
        PasteType::File | PasteType::RemoteFile => Some("file"),
        PasteType::Url => Some("url"),
        PasteType::Oneshot | PasteType::OneshotUrl | PasteType::ProtectedFile => None,
    }
}

fn active_public_link_key(paste: &NewPaste, now: i64) -> Option<&str> {
    if paste.owner_principal_id.is_some() && paste.expires_at.is_none_or(|expiry| expiry > now) {
        Some(&paste.public_filename)
    } else {
        None
    }
}

async fn prepare_public_link(
    transaction: &mut Transaction<'_, Sqlite>,
    link_key: &str,
    now: i64,
) -> Result<(), StoreError> {
    clear_expired_public_link(transaction, link_key, now).await?;
    ensure_public_link_available(transaction, link_key, now).await
}

async fn clear_expired_public_link(
    transaction: &mut Transaction<'_, Sqlite>,
    link_key: &str,
    now: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE pastes SET link_key = NULL \
         WHERE link_key = ? AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(link_key)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn ensure_public_link_available(
    transaction: &mut Transaction<'_, Sqlite>,
    link_key: &str,
    now: i64,
) -> Result<(), StoreError> {
    if public_link_is_active(transaction, link_key, now).await? {
        return Err(StoreError::PublicFilenameConflict(link_key.to_string()));
    }
    Ok(())
}

async fn public_link_is_active(
    transaction: &mut Transaction<'_, Sqlite>,
    link_key: &str,
    now: i64,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "SELECT 1 FROM pastes \
         WHERE (link_key = ? OR (link_key IS NULL AND public_filename = ?)) \
           AND (expires_at IS NULL OR expires_at > ?) \
         LIMIT 1",
    )
    .bind(link_key)
    .bind(link_key)
    .bind(now)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some())
}

async fn find_dedup_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    owner_principal_id: i64,
    dedup_key: &str,
) -> Result<Option<PasteRecord>, StoreError> {
    let statement = paste_select("WHERE owner_principal_id = ? AND dedup_key = ? LIMIT 1");
    let row = sqlx::query(&statement)
        .bind(owner_principal_id)
        .bind(dedup_key)
        .fetch_optional(&mut **transaction)
        .await?;
    row.as_ref().map(paste_from_row).transpose()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.is_unique_violation())
}

fn validate_new_paste(paste: &NewPaste) -> Result<(), StoreError> {
    if paste.public_filename.is_empty() {
        return Err(StoreError::InvalidInput(String::from(
            "paste public filename cannot be empty",
        )));
    }
    if paste.storage_path.as_os_str().is_empty() {
        return Err(StoreError::InvalidInput(String::from(
            "paste storage path cannot be empty",
        )));
    }
    if paste.content_hash.trim().is_empty() {
        return Err(StoreError::InvalidInput(String::from(
            "paste content hash cannot be empty",
        )));
    }
    i64::try_from(paste.size_bytes)
        .map(|_| ())
        .map_err(|_| StoreError::InvalidInput(String::from("paste size is too large")))
}

fn path_to_string(path: &Path) -> Result<&str, StoreError> {
    path.to_str().ok_or_else(|| {
        StoreError::InvalidInput(String::from("SQLite paste paths must be valid UTF-8"))
    })
}

fn validate_return_to(return_to: &str) -> Result<(), StoreError> {
    let lowercase = return_to.to_ascii_lowercase();
    if !return_to.starts_with('/')
        || return_to.starts_with("//")
        || lowercase.starts_with("/%2f")
        || lowercase.starts_with("/%5c")
        || return_to.contains('\\')
        || return_to.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidInput(String::from(
            "return_to must be a relative same-origin path",
        )));
    }
    let base = Url::parse("https://rustypaste.invalid/")
        .map_err(|error| StoreError::InvalidData(error.to_string()))?;
    let resolved = base.join(return_to).map_err(|_| {
        StoreError::InvalidInput(String::from(
            "return_to must be a relative same-origin path",
        ))
    })?;
    if resolved.origin() != base.origin() {
        return Err(StoreError::InvalidInput(String::from(
            "return_to must be a relative same-origin path",
        )));
    }
    Ok(())
}

fn normalize_user_code(value: &str) -> String {
    let compact: String = value
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect();
    if compact.len() == 8 {
        format!("{}-{}", &compact[..4], &compact[4..])
    } else {
        compact
    }
}

fn generate_user_code() -> Result<String, StoreError> {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut random = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| StoreError::RandomGeneration)?;
    let code: String = random
        .iter()
        .map(|value| char::from(ALPHABET[usize::from(*value) % ALPHABET.len()]))
        .collect();
    Ok(format!("{}-{}", &code[..4], &code[4..]))
}

fn generate_secret() -> Result<SecretString, StoreError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StoreError::RandomGeneration)?;
    Ok(SecretString::new(URL_SAFE_NO_PAD.encode(bytes)))
}

fn secret_hash(secret: &str) -> Vec<u8> {
    digest(&SHA256, secret.as_bytes()).as_ref().to_vec()
}

fn unix_now() -> Result<i64, StoreError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidSystemTime)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| StoreError::DurationOverflow)
}

fn duration_seconds(duration: Duration) -> Result<i64, StoreError> {
    i64::try_from(duration.as_secs()).map_err(|_| StoreError::DurationOverflow)
}

fn expiry_from(now: i64, lifetime: Duration) -> Result<i64, StoreError> {
    let lifetime = duration_seconds(lifetime)?;
    if lifetime == 0 {
        return Err(StoreError::InvalidInput(String::from(
            "credential and flow lifetimes must be greater than zero",
        )));
    }
    now.checked_add(lifetime)
        .ok_or(StoreError::DurationOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_TIMEOUT: Duration = Duration::from_secs(90 * 24 * 60 * 60);

    async fn test_store() -> Result<(TempDir, AuthStore), StoreError> {
        let directory = tempfile::tempdir()?;
        let store = AuthStore::open(
            &directory.path().join("auth.sqlite3"),
            TEST_TIMEOUT,
            TEST_TIMEOUT,
        )
        .await?;
        Ok((directory, store))
    }

    #[cfg(unix)]
    #[actix_rt::test]
    async fn database_file_permissions_are_private() -> Result<(), StoreError> {
        use std::os::unix::fs::PermissionsExt;

        let (directory, store) = test_store().await?;
        let mode = std::fs::metadata(directory.path().join("auth.sqlite3"))?
            .permissions()
            .mode();
        assert_eq!(0o600, mode & 0o777);
        store.close().await;
        Ok(())
    }

    #[actix_rt::test]
    async fn persists_stable_principals_and_hashed_revocable_credentials() -> Result<(), StoreError>
    {
        let (directory, store) = test_store().await?;
        let principal = store
            .upsert_oidc_principal(
                "https://identity.example.com",
                "subject-1",
                Some("first@example.com"),
                Some("First Name"),
                false,
            )
            .await?;
        let refreshed = store
            .upsert_oidc_principal(
                "https://identity.example.com",
                "subject-1",
                Some("new@example.com"),
                Some("New Name"),
                true,
            )
            .await?;
        assert_eq!(principal.id, refreshed.id);
        assert_eq!(Some(String::from("new@example.com")), refreshed.email);
        assert!(refreshed.is_admin);
        assert!(refreshed.can_delete_all);

        let legacy_delete = store
            .upsert_legacy_principal("deprecated-delete", true)
            .await?;
        assert!(!legacy_delete.is_admin);
        assert!(legacy_delete.can_delete_all);

        let session = store.create_browser_session(principal.id).await?;
        let stored_hash: Vec<u8> =
            sqlx::query("SELECT secret_hash FROM browser_sessions WHERE id = ?")
                .bind(session.id)
                .fetch_one(&store.pool)
                .await?
                .try_get("secret_hash")?;
        assert_eq!(32, stored_hash.len());
        assert_ne!(session.secret.expose().as_bytes(), stored_hash.as_slice());
        let short_expiry = unix_now()? + 60;
        sqlx::query("UPDATE browser_sessions SET last_used_at = ?, expires_at = ? WHERE id = ?")
            .bind(unix_now()? - ROLLING_UPDATE_INTERVAL_SECONDS - 1)
            .bind(short_expiry)
            .bind(session.id)
            .execute(&store.pool)
            .await?;
        let authenticated = store
            .authenticate_browser_session(session.secret.expose())
            .await?
            .expect("active session");
        assert_eq!(principal.id, authenticated.principal.id);
        assert!(authenticated.expires_at > short_expiry);
        assert!(
            store
                .revoke_browser_session(session.secret.expose())
                .await?
        );
        assert!(store
            .authenticate_browser_session(session.secret.expose())
            .await?
            .is_none());

        let token = store.create_api_token(principal.id, Some("test")).await?;
        sqlx::query("UPDATE api_tokens SET expires_at = 0 WHERE id = ?")
            .bind(token.id)
            .execute(&store.pool)
            .await?;
        assert!(store
            .authenticate_api_token(token.secret.expose())
            .await?
            .is_none());

        let database_path = directory.path().join("auth.sqlite3");
        store.close().await;
        let reopened = AuthStore::open(&database_path, TEST_TIMEOUT, TEST_TIMEOUT).await?;
        assert_eq!(
            Some(principal.id),
            reopened.get_principal(principal.id).await?.map(|p| p.id)
        );
        reopened.close().await;
        Ok(())
    }

    #[actix_rt::test]
    async fn dynamically_issued_credentials_are_bounded_per_principal() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let principal = store
            .upsert_oidc_principal(
                "https://identity.example.com",
                "bounded-credentials",
                None,
                None,
                false,
            )
            .await?;
        let static_token = SecretString::new("configured-service-token");
        store
            .provision_static_api_token(principal.id, &static_token, Some("service:configured"))
            .await?;

        let mut sessions = Vec::new();
        let mut tokens = Vec::new();
        for _ in 0..=MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL {
            sessions.push(store.create_browser_session(principal.id).await?);
            tokens.push(
                store
                    .create_api_token(principal.id, Some("rustypaste-cli"))
                    .await?,
            );
        }

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM browser_sessions WHERE principal_id = ?")
                .bind(principal.id)
                .fetch_one(&store.pool)
                .await?;
        let dynamic_token_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_tokens WHERE principal_id = ? AND label = 'rustypaste-cli'",
        )
        .bind(principal.id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL, session_count);
        assert_eq!(MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL, dynamic_token_count);

        assert!(store
            .authenticate_browser_session(sessions.first().expect("oldest session").secret.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(tokens.first().expect("oldest token").secret.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_browser_session(sessions.last().expect("newest session").secret.expose())
            .await?
            .is_some());
        assert!(store
            .authenticate_api_token(tokens.last().expect("newest token").secret.expose())
            .await?
            .is_some());
        assert!(store
            .authenticate_api_token(static_token.expose())
            .await?
            .is_some());
        Ok(())
    }

    #[actix_rt::test]
    async fn device_delivery_respects_the_dynamic_api_token_limit() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let principal = store
            .upsert_oidc_principal(
                "https://identity.example.com",
                "bounded-device-credentials",
                None,
                None,
                false,
            )
            .await?;
        let mut existing_tokens = Vec::new();
        for _ in 0..MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL {
            existing_tokens.push(
                store
                    .create_api_token(principal.id, Some("rustypaste-cli"))
                    .await?,
            );
        }
        let authorization = store
            .start_device_flow(
                "retention test",
                Duration::from_secs(600),
                Duration::from_secs(1),
            )
            .await?;
        assert!(
            store
                .approve_device_flow(&authorization.user_code, principal.id)
                .await?
        );
        let delivered = match store
            .poll_device_flow(authorization.device_code.expose(), Some("rustypaste-cli"))
            .await?
        {
            DevicePoll::Authorized { credential, .. } => credential,
            result => panic!("unexpected device poll result: {result:?}"),
        };

        let token_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_tokens WHERE principal_id = ? AND label = 'rustypaste-cli'",
        )
        .bind(principal.id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(MAX_ACTIVE_CREDENTIALS_PER_PRINCIPAL, token_count);
        assert!(store
            .authenticate_api_token(
                existing_tokens
                    .first()
                    .expect("oldest token")
                    .secret
                    .expose(),
            )
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(delivered.secret.expose())
            .await?
            .is_some());
        Ok(())
    }

    #[actix_rt::test]
    async fn purge_expired_deletes_revoked_and_expired_credentials() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let principal = store
            .upsert_service_principal("credential-purge", false)
            .await?;
        let revoked_session = store.create_browser_session(principal.id).await?;
        let expired_session = store.create_browser_session(principal.id).await?;
        let revoked_token = store.create_api_token(principal.id, Some("test")).await?;
        let expired_token = store.create_api_token(principal.id, Some("test")).await?;

        assert!(
            store
                .revoke_browser_session(revoked_session.secret.expose())
                .await?
        );
        assert!(
            store
                .revoke_api_token(revoked_token.secret.expose())
                .await?
        );
        sqlx::query("UPDATE browser_sessions SET expires_at = 0 WHERE id = ?")
            .bind(expired_session.id)
            .execute(&store.pool)
            .await?;
        sqlx::query("UPDATE api_tokens SET expires_at = 0 WHERE id = ?")
            .bind(expired_token.id)
            .execute(&store.pool)
            .await?;

        assert_eq!(4, store.purge_expired().await?);
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM browser_sessions WHERE principal_id = ?")
                .bind(principal.id)
                .fetch_one(&store.pool)
                .await?;
        let token_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE principal_id = ?")
                .bind(principal.id)
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(0, session_count);
        assert_eq!(0, token_count);
        Ok(())
    }

    #[actix_rt::test]
    async fn managed_token_rotation_revokes_removed_tokens_but_not_cli_tokens(
    ) -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let service = store.upsert_service_principal("ci", true).await?;
        let legacy = store
            .upsert_legacy_principal("deprecated-delete-tokens", true)
            .await?;
        let legacy_auth = store
            .upsert_legacy_principal("deprecated-auth-tokens", false)
            .await?;
        let old_service = SecretString::new("old-service-token");
        let old_legacy = SecretString::new("old-legacy-token");
        let old_legacy_auth = SecretString::new("old-legacy-auth-token");
        store
            .provision_static_api_token(service.id, &old_service, Some("service:ci"))
            .await?;
        store
            .provision_static_api_token(legacy.id, &old_legacy, Some("legacy-delete"))
            .await?;
        store
            .provision_static_api_token(legacy_auth.id, &old_legacy_auth, Some("legacy-auth"))
            .await?;
        let cli = store
            .create_api_token(service.id, Some("rustypaste-cli"))
            .await?;

        assert_eq!(3, store.revoke_managed_api_tokens().await?);
        assert!(store
            .authenticate_api_token(old_service.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(old_legacy.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(old_legacy_auth.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(cli.secret.expose())
            .await?
            .is_some());

        let replacement = SecretString::new("replacement-service-token");
        store
            .provision_static_api_token(service.id, &replacement, Some("service:ci"))
            .await?;
        assert!(store
            .authenticate_api_token(replacement.expose())
            .await?
            .is_some());
        assert_eq!(1, store.revoke_managed_api_tokens().await?);
        assert!(store
            .authenticate_api_token(replacement.expose())
            .await?
            .is_none());
        assert!(store
            .authenticate_api_token(cli.secret.expose())
            .await?
            .is_some());
        Ok(())
    }

    #[test]
    fn return_to_accepts_only_same_origin_relative_paths() {
        for value in ["/", "/paste.txt", "/paste.txt?download=true"] {
            assert!(validate_return_to(value).is_ok(), "rejected {value:?}");
        }
        for value in [
            "",
            "https://evil.example/",
            "//evil.example/",
            "///evil.example/",
            "/\\evil.example/",
            "/path\\evil.example/",
            "/%2fevil.example/",
            "/%2Fevil.example/",
            "/%5cevil.example/",
            "/path\nnext",
        ] {
            assert!(validate_return_to(value).is_err(), "accepted {value:?}");
        }
    }

    #[actix_rt::test]
    async fn transient_flow_admission_is_bounded_and_purges_expired_rows() -> Result<(), StoreError>
    {
        let (_directory, store) = test_store().await?;
        let now = unix_now()?;
        sqlx::query(
            "WITH RECURSIVE sequence(value) AS (\
                 SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < ?\
             ) \
             INSERT INTO oauth_flows \
                 (state_hash, code_verifier, nonce, return_to, created_at, expires_at) \
             SELECT printf('oauth-%d', value), 'verifier', 'nonce', '/', ?, ? FROM sequence",
        )
        .bind(MAX_ACTIVE_OAUTH_FLOWS)
        .bind(now)
        .bind(now + 600)
        .execute(&store.pool)
        .await?;
        assert!(matches!(
            store
                .store_oauth_flow(
                    "overflow",
                    "verifier",
                    "nonce",
                    "/",
                    Duration::from_secs(600),
                )
                .await,
            Err(StoreError::CapacityExceeded(_))
        ));
        sqlx::query("UPDATE oauth_flows SET expires_at = 0")
            .execute(&store.pool)
            .await?;
        store
            .store_oauth_flow(
                "admitted",
                "verifier",
                "nonce",
                "/",
                Duration::from_secs(600),
            )
            .await?;
        let oauth_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_flows")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(1, oauth_count);

        sqlx::query(
            "WITH RECURSIVE sequence(value) AS (\
                 SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < ?\
             ) \
             INSERT INTO cli_device_flows \
                 (device_code_hash, user_code, client_name, created_at, expires_at, \
                  poll_interval_seconds) \
             SELECT printf('device-%d', value), printf('code-%d', value), 'rpaste', ?, ?, 5 \
             FROM sequence",
        )
        .bind(MAX_ACTIVE_DEVICE_FLOWS)
        .bind(now)
        .bind(now + 600)
        .execute(&store.pool)
        .await?;
        assert!(matches!(
            store
                .start_device_flow(
                    "rpaste overflow",
                    Duration::from_secs(600),
                    Duration::from_secs(5),
                )
                .await,
            Err(StoreError::CapacityExceeded(_))
        ));
        sqlx::query("UPDATE cli_device_flows SET expires_at = 0")
            .execute(&store.pool)
            .await?;
        let admitted = store
            .start_device_flow(
                "rpaste admitted",
                Duration::from_secs(600),
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!("rpaste admitted", admitted.client_name);
        let device_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cli_device_flows")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(1, device_count);
        Ok(())
    }

    #[actix_rt::test]
    async fn oauth_and_device_flows_are_consumed_once() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let principal = store
            .upsert_oidc_principal(
                "https://identity.example.com",
                "subject-1",
                None,
                None,
                false,
            )
            .await?;

        store
            .store_oauth_flow(
                "oauth-state",
                "pkce-verifier",
                "oidc-nonce",
                "/private/paste?raw=1",
                Duration::from_secs(600),
            )
            .await?;
        let oauth = store
            .consume_oauth_flow("oauth-state")
            .await?
            .expect("stored OAuth flow");
        assert_eq!("pkce-verifier", oauth.code_verifier.expose());
        assert_eq!("oidc-nonce", oauth.nonce.expose());
        assert_eq!("/private/paste?raw=1", oauth.return_to);
        assert!(store.consume_oauth_flow("oauth-state").await?.is_none());

        let device = store
            .start_device_flow(
                "rpaste on test host",
                Duration::from_secs(600),
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!("rpaste on test host", device.client_name);
        assert_eq!(
            Some(String::from("rpaste on test host")),
            store
                .get_device_flow_client_name(&device.user_code.to_lowercase())
                .await?
        );
        assert!(matches!(
            store
                .poll_device_flow(device.device_code.expose(), Some("cli"))
                .await?,
            DevicePoll::Pending
        ));
        assert!(
            store
                .approve_device_flow(&device.user_code.to_lowercase(), principal.id)
                .await?
        );
        assert!(matches!(
            store
                .poll_device_flow(device.device_code.expose(), Some("cli"))
                .await?,
            DevicePoll::SlowDown
        ));
        sqlx::query("UPDATE cli_device_flows SET last_polled_at = 0 WHERE user_code = ?")
            .bind(&device.user_code)
            .execute(&store.pool)
            .await?;
        let credential = match store
            .poll_device_flow(device.device_code.expose(), Some("cli"))
            .await?
        {
            DevicePoll::Authorized {
                principal: approved,
                credential,
            } => {
                assert_eq!(principal.id, approved.id);
                credential
            }
            result => panic!("unexpected device poll result: {result:?}"),
        };
        assert_eq!(
            Some(principal.id),
            store
                .authenticate_api_token(credential.secret.expose())
                .await?
                .map(|authenticated| authenticated.principal.id)
        );
        assert!(matches!(
            store
                .poll_device_flow(device.device_code.expose(), Some("cli"))
                .await?,
            DevicePoll::Consumed
        ));
        Ok(())
    }

    #[actix_rt::test]
    async fn opt_in_deduplication_is_owner_and_type_scoped_under_concurrency(
    ) -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let owner = store.upsert_service_principal("dedup-owner", false).await?;
        let now = unix_now()?;
        let first = NewPaste {
            owner_principal_id: Some(owner.id),
            public_filename: String::from("first.txt"),
            storage_path: PathBuf::from("/uploads/first.txt"),
            paste_type: PasteType::File,
            created_at: now,
            size_bytes: 10,
            expires_at: None,
            content_hash: String::from("shared-digest"),
        };
        let second = NewPaste {
            public_filename: String::from("second.txt"),
            storage_path: PathBuf::from("/uploads/second.txt"),
            paste_type: PasteType::RemoteFile,
            created_at: now + 1,
            ..first.clone()
        };
        let (first_result, second_result) = futures_util::future::join(
            store.insert_paste_deduplicated(&first),
            store.insert_paste_deduplicated(&second),
        )
        .await;
        let first_result = first_result?;
        let second_result = second_result?;
        let (inserted, duplicate) = match (&first_result, &second_result) {
            (PasteInsert::Inserted(inserted), PasteInsert::Duplicate(duplicate))
            | (PasteInsert::Duplicate(duplicate), PasteInsert::Inserted(inserted)) => {
                (inserted, duplicate)
            }
            results => panic!("unexpected dedup results: {results:?}"),
        };
        assert_eq!(inserted.id, duplicate.id);

        let occupied_link = NewPaste {
            public_filename: String::from("occupied.txt"),
            storage_path: PathBuf::from("/uploads/occupied.txt"),
            created_at: now + 2,
            content_hash: String::from("different-digest"),
            ..first.clone()
        };
        assert!(matches!(
            store.insert_paste_deduplicated(&occupied_link).await?,
            PasteInsert::Inserted(_)
        ));
        let content_duplicate_with_occupied_link = NewPaste {
            storage_path: PathBuf::from("/uploads/duplicate-at-occupied-link.txt"),
            content_hash: first.content_hash.clone(),
            ..occupied_link.clone()
        };
        assert!(matches!(
            store
                .insert_paste_deduplicated(&content_duplicate_with_occupied_link)
                .await?,
            PasteInsert::Duplicate(record) if record.id == inserted.id
        ));

        let same_url_content = NewPaste {
            public_filename: String::from("redirect"),
            storage_path: PathBuf::from("/uploads/url/redirect"),
            paste_type: PasteType::Url,
            created_at: now + 3,
            ..first.clone()
        };
        assert!(matches!(
            store.insert_paste_deduplicated(&same_url_content).await?,
            PasteInsert::Inserted(_)
        ));

        let other_owner = store.upsert_service_principal("other-owner", false).await?;
        let other_owner_paste = NewPaste {
            owner_principal_id: Some(other_owner.id),
            public_filename: String::from("other-owner.txt"),
            storage_path: PathBuf::from("/uploads/other-owner.txt"),
            created_at: now + 4,
            ..first.clone()
        };
        assert!(matches!(
            store.insert_paste_deduplicated(&other_owner_paste).await?,
            PasteInsert::Inserted(_)
        ));

        let unrestricted_one = NewPaste {
            public_filename: String::from("unrestricted-one.txt"),
            storage_path: PathBuf::from("/uploads/unrestricted-one.txt"),
            created_at: now + 5,
            ..first.clone()
        };
        let unrestricted_two = NewPaste {
            public_filename: String::from("unrestricted-two.txt"),
            storage_path: PathBuf::from("/uploads/unrestricted-two.txt"),
            created_at: now + 6,
            ..first.clone()
        };
        store.insert_paste(&unrestricted_one).await?;
        store.insert_paste(&unrestricted_two).await?;
        assert_eq!(5, store.list_owner_pastes(owner.id).await?.len());
        assert_eq!(1, store.list_owner_pastes(other_owner.id).await?.len());
        Ok(())
    }

    #[actix_rt::test]
    async fn reserves_public_links_across_owners_types_and_expiring_paths() -> Result<(), StoreError>
    {
        let (_directory, store) = test_store().await?;
        let first_owner = store
            .upsert_service_principal("link-owner-1", false)
            .await?;
        let second_owner = store
            .upsert_service_principal("link-owner-2", false)
            .await?;
        let now = unix_now()?;
        let expires_at = now + 600;
        let first = NewPaste {
            owner_principal_id: Some(first_owner.id),
            public_filename: String::from("shared.txt"),
            storage_path: PathBuf::from(format!("/uploads/shared.txt.{}", expires_at * 1_000)),
            paste_type: PasteType::File,
            created_at: now,
            size_bytes: 10,
            expires_at: Some(expires_at),
            content_hash: String::from("first-digest"),
        };
        let first_record = store.insert_paste(&first).await?;
        let conflicting = NewPaste {
            owner_principal_id: Some(second_owner.id),
            storage_path: PathBuf::from("/uploads/url/shared.txt"),
            paste_type: PasteType::Url,
            expires_at: None,
            content_hash: String::from("second-digest"),
            ..first.clone()
        };
        assert!(matches!(
            store.insert_paste(&conflicting).await,
            Err(StoreError::PublicFilenameConflict(filename)) if filename == "shared.txt"
        ));

        sqlx::query("UPDATE pastes SET expires_at = ? WHERE id = ?")
            .bind(now - 1)
            .bind(first_record.id)
            .execute(&store.pool)
            .await?;
        let replacement = store.insert_paste(&conflicting).await?;
        assert_eq!(Some(second_owner.id), replacement.owner_principal_id);
        let old_link_key: Option<String> =
            sqlx::query_scalar("SELECT link_key FROM pastes WHERE id = ?")
                .bind(first_record.id)
                .fetch_one(&store.pool)
                .await?;
        let replacement_link_key: Option<String> =
            sqlx::query_scalar("SELECT link_key FROM pastes WHERE id = ?")
                .bind(replacement.id)
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(None, old_link_key);
        assert_eq!(Some(String::from("shared.txt")), replacement_link_key);
        Ok(())
    }

    #[actix_rt::test]
    async fn active_reconciled_legacy_links_block_new_reservations() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let owner = store.upsert_service_principal("new-owner", false).await?;
        let now = unix_now()?;
        let legacy = NewPaste {
            owner_principal_id: None,
            public_filename: String::from("legacy.txt"),
            storage_path: PathBuf::from("/uploads/legacy.txt"),
            paste_type: PasteType::File,
            created_at: now - 10,
            size_bytes: 7,
            expires_at: None,
            content_hash: String::from("legacy-digest"),
        };
        store
            .reconcile_pastes(std::slice::from_ref(&legacy))
            .await?;
        let legacy_link_key: Option<String> =
            sqlx::query_scalar("SELECT link_key FROM pastes WHERE public_filename = 'legacy.txt'")
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(None, legacy_link_key);

        let new_paste = NewPaste {
            owner_principal_id: Some(owner.id),
            storage_path: PathBuf::from("/uploads/url/legacy.txt"),
            paste_type: PasteType::Url,
            content_hash: String::from("new-digest"),
            ..legacy
        };
        assert!(matches!(
            store.insert_paste(&new_paste).await,
            Err(StoreError::PublicFilenameConflict(filename)) if filename == "legacy.txt"
        ));
        Ok(())
    }

    #[actix_rt::test]
    async fn concurrent_same_name_inserts_have_one_public_link_winner() -> Result<(), StoreError> {
        let (_directory, store) = test_store().await?;
        let first_owner = store
            .upsert_service_principal("concurrent-owner-1", false)
            .await?;
        let second_owner = store
            .upsert_service_principal("concurrent-owner-2", false)
            .await?;
        let now = unix_now()?;
        let first = NewPaste {
            owner_principal_id: Some(first_owner.id),
            public_filename: String::from("same-name.txt"),
            storage_path: PathBuf::from("/uploads/same-name.txt"),
            paste_type: PasteType::File,
            created_at: now,
            size_bytes: 10,
            expires_at: None,
            content_hash: String::from("first-content"),
        };
        let second = NewPaste {
            owner_principal_id: Some(second_owner.id),
            storage_path: PathBuf::from("/uploads/url/same-name.txt"),
            paste_type: PasteType::Url,
            content_hash: String::from("second-content"),
            ..first.clone()
        };
        let results =
            futures_util::future::join(store.insert_paste(&first), store.insert_paste(&second))
                .await;
        assert!(matches!(
            results,
            (Ok(_), Err(StoreError::PublicFilenameConflict(_)))
                | (Err(StoreError::PublicFilenameConflict(_)), Ok(_))
        ));
        assert_eq!(1, store.list_all_pastes().await?.len());
        Ok(())
    }

    #[actix_rt::test]
    async fn scopes_paste_metadata_by_owner_and_reconciles_legacy_files() -> Result<(), StoreError>
    {
        let (_directory, store) = test_store().await?;
        let first = store.upsert_service_principal("first", false).await?;
        let second = store.upsert_service_principal("second", false).await?;
        let now = unix_now()?;
        let first_paste = NewPaste {
            owner_principal_id: Some(first.id),
            public_filename: String::from("first.txt"),
            storage_path: PathBuf::from("/uploads/first.txt"),
            paste_type: PasteType::File,
            created_at: now,
            size_bytes: 10,
            expires_at: None,
            content_hash: String::from("same-digest"),
        };
        let second_paste = NewPaste {
            owner_principal_id: Some(second.id),
            public_filename: String::from("second.txt"),
            storage_path: PathBuf::from("/uploads/second.txt"),
            paste_type: PasteType::File,
            created_at: now + 1,
            size_bytes: 10,
            expires_at: None,
            content_hash: String::from("same-digest"),
        };
        let first_record = store.insert_paste(&first_paste).await?;
        store.insert_paste(&second_paste).await?;
        assert_eq!(
            Some(first_record.id),
            store
                .find_owner_duplicate(first.id, "same-digest")
                .await?
                .map(|paste| paste.id)
        );
        assert_eq!(1, store.list_owner_pastes(first.id).await?.len());
        assert_eq!(1, store.list_owner_pastes(second.id).await?.len());
        assert_eq!(2, store.list_all_pastes().await?.len());

        let legacy = NewPaste {
            owner_principal_id: None,
            public_filename: String::from("legacy.txt"),
            storage_path: PathBuf::from("/uploads/legacy.txt"),
            paste_type: PasteType::File,
            created_at: now - 10,
            size_bytes: 7,
            expires_at: None,
            content_hash: String::from("legacy-digest"),
        };
        let result = store
            .reconcile_pastes(&[first_paste.clone(), second_paste.clone(), legacy.clone()])
            .await?;
        assert_eq!(
            ReconcileResult {
                inserted: 1,
                removed: 0
            },
            result
        );
        assert!(store
            .find_paste_by_storage_path(&legacy.storage_path)
            .await?
            .is_some_and(|paste| paste.owner_principal_id.is_none()));

        let result = store
            .reconcile_pastes(&[second_paste.clone(), legacy])
            .await?;
        assert_eq!(
            ReconcileResult {
                inserted: 0,
                removed: 1
            },
            result
        );
        assert!(store.get_paste(first_record.id).await?.is_none());
        assert_eq!(
            Some(second.id),
            store
                .list_owner_pastes(second.id)
                .await?
                .first()
                .and_then(|paste| paste.owner_principal_id)
        );
        Ok(())
    }
}
