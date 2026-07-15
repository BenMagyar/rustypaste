use crate::config::{AuthConfig, Config, TokenType};
use crate::oidc::OidcClient;
use crate::store::{AuthStore, Principal};
use actix_web::body::MessageBody;
use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{ACCEPT, AUTHORIZATION, ORIGIN};
use actix_web::http::Method;
use actix_web::{error, web, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::io::{Error as IoError, ErrorKind};
use std::rc::Rc;
use std::sync::RwLock;
use std::task::{Context, Poll};
use url::Url;

/// Name of the opaque browser-session cookie.
pub const SESSION_COOKIE: &str = "rustypaste_session";

/// Initialized OIDC client and persistent authentication store.
#[derive(Debug)]
pub struct AuthRuntime {
    /// Validated authentication configuration.
    pub config: AuthConfig,
    /// SQLite authentication and ownership store.
    pub store: AuthStore,
    /// Discovered OpenID Connect client.
    pub oidc: OidcClient,
    /// Externally visible server URL without a trailing slash.
    pub server_url: String,
}

impl AuthRuntime {
    /// Initializes authentication when an `[auth]` table is present.
    pub async fn initialize(config: &Config) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let Some(auth_config) = config.auth.clone() else {
            return Ok(None);
        };
        auth_config
            .validate(&config.server)
            .map_err(|message| IoError::new(ErrorKind::InvalidInput, message))?;
        let server_url = config
            .server
            .url
            .as_deref()
            .ok_or_else(|| {
                IoError::new(ErrorKind::InvalidInput, "server URL is required for OIDC")
            })?
            .trim_end_matches('/')
            .to_string();
        let store = AuthStore::connect(&auth_config).await?;
        store.revoke_managed_api_tokens().await?;

        for (name, account) in &auth_config.service_accounts {
            let principal = store.upsert_service_principal(name, account.admin).await?;
            let token = account
                .resolve_token()
                .map_err(|message| IoError::new(ErrorKind::InvalidInput, message))?;
            store
                .provision_static_api_token(principal.id, &token, Some(&format!("service:{name}")))
                .await?;
        }

        let auth_tokens = config.get_tokens(TokenType::Auth).unwrap_or_default();
        let delete_tokens = config.get_tokens(TokenType::Delete).unwrap_or_default();
        let upload_tokens = auth_tokens.difference(&delete_tokens);
        if upload_tokens.clone().next().is_some() {
            let principal = store
                .upsert_legacy_principal("deprecated-auth-tokens", false)
                .await?;
            for token in upload_tokens {
                store
                    .provision_static_api_token(
                        principal.id,
                        &crate::config::SecretString::new(token.clone()),
                        Some("legacy-auth"),
                    )
                    .await?;
            }
        }
        if !delete_tokens.is_empty() {
            let principal = store
                .upsert_legacy_principal("deprecated-delete-tokens", true)
                .await?;
            for token in delete_tokens {
                store
                    .provision_static_api_token(
                        principal.id,
                        &crate::config::SecretString::new(token),
                        Some("legacy-delete"),
                    )
                    .await?;
            }
        }

        let oidc = OidcClient::discover(
            auth_config.oidc.issuer_url.clone(),
            auth_config.oidc.client_id.clone(),
            auth_config.oidc.client_secret.expose().to_string(),
            format!("{server_url}/auth/callback"),
            auth_config.oidc.scopes.clone(),
        )
        .await?;

        Ok(Some(Self {
            config: auth_config,
            store,
            oidc,
            server_url,
        }))
    }

    /// Builds a secure session cookie whose server-side expiry remains authoritative.
    pub fn session_cookie(&self, value: String) -> Cookie<'static> {
        let seconds = i64::try_from(self.config.session_idle_timeout.as_secs()).unwrap_or(i64::MAX);
        Cookie::build(SESSION_COOKIE, value)
            .path(public_cookie_path(&self.server_url))
            .http_only(true)
            .secure(self.config.secure_cookies)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::seconds(seconds))
            .finish()
    }

    /// Builds a removal cookie for logout and expired local sessions.
    pub fn removal_cookie(&self) -> Cookie<'static> {
        let mut cookie = self.session_cookie(String::new());
        cookie.make_removal();
        cookie
    }
}

/// Credential kind used for the current request.
#[derive(Clone)]
pub enum CredentialSource {
    /// Opaque browser session.
    Browser {
        /// Plaintext session secret retained only for rolling cookie refresh and logout.
        secret: String,
    },
    /// CLI, service-account, or legacy API token.
    Api {
        /// Plaintext API secret retained only for token self-revocation.
        secret: String,
    },
    /// No persistent identity because OIDC is disabled for this deployment.
    LegacyPublic,
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Browser { .. } => formatter.write_str("Browser([REDACTED])"),
            Self::Api { .. } => formatter.write_str("Api([REDACTED])"),
            Self::LegacyPublic => formatter.write_str("LegacyPublic"),
        }
    }
}

/// Authenticated identity injected into protected handlers.
#[derive(Clone, Debug)]
pub struct RequestAuth {
    /// Persisted principal when OIDC authentication is enabled.
    pub principal: Option<Principal>,
    /// Credential database identifier.
    pub credential_id: Option<i64>,
    /// Rolling credential expiry as Unix seconds.
    pub expires_at: Option<i64>,
    /// Whether this identity may administer all pastes.
    pub global_delete: bool,
    /// Credential source for logout and cookie refresh.
    pub source: CredentialSource,
}

impl RequestAuth {
    /// Returns the persisted owner identifier, if ownership is enabled.
    pub fn principal_id(&self) -> Option<i64> {
        self.principal.as_ref().map(|principal| principal.id)
    }

    /// Returns whether this identity has administrator privileges.
    pub fn is_admin(&self) -> bool {
        self.principal
            .as_ref()
            .is_some_and(|principal| principal.is_admin)
    }

    /// Returns the current browser-session secret for logout.
    pub fn browser_secret(&self) -> Option<&str> {
        match &self.source {
            CredentialSource::Browser { secret } => Some(secret),
            _ => None,
        }
    }

    /// Returns the current API-token secret for self-revocation.
    pub fn api_secret(&self) -> Option<&str> {
        match &self.source {
            CredentialSource::Api { secret } => Some(secret),
            _ => None,
        }
    }
}

impl FromRequest for RequestAuth {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move {
            let auth = if let Some(runtime) = request.app_data::<web::Data<AuthRuntime>>() {
                authenticate_oidc_request(&request, runtime).await?
            } else {
                authenticate_legacy_request(&request)?
            };
            request.extensions_mut().insert(auth.clone());
            Ok(auth)
        })
    }
}

async fn authenticate_oidc_request(
    request: &HttpRequest,
    runtime: &AuthRuntime,
) -> Result<RequestAuth, Error> {
    if let Some(secret) = authorization_secret(request) {
        if let Some(authenticated) = runtime
            .store
            .authenticate_api_token(secret)
            .await
            .map_err(error::ErrorInternalServerError)?
        {
            let global_delete =
                authenticated.principal.is_admin || authenticated.principal.can_delete_all;
            return Ok(RequestAuth {
                principal: Some(authenticated.principal),
                credential_id: Some(authenticated.credential_id),
                expires_at: Some(authenticated.expires_at),
                global_delete,
                source: CredentialSource::Api {
                    secret: secret.to_string(),
                },
            });
        }
    }

    if let Some(cookie) = request.cookie(SESSION_COOKIE) {
        let secret = cookie.value().to_string();
        if let Some(authenticated) = runtime
            .store
            .authenticate_browser_session(&secret)
            .await
            .map_err(error::ErrorInternalServerError)?
        {
            validate_cookie_origin(request, runtime)?;
            let global_delete =
                authenticated.principal.is_admin || authenticated.principal.can_delete_all;
            return Ok(RequestAuth {
                principal: Some(authenticated.principal),
                credential_id: Some(authenticated.credential_id),
                expires_at: Some(authenticated.expires_at),
                global_delete,
                source: CredentialSource::Browser { secret },
            });
        }
    }

    Err(unauthorized_request(request, runtime))
}

fn authenticate_legacy_request(request: &HttpRequest) -> Result<RequestAuth, Error> {
    let config = request
        .app_data::<web::Data<RwLock<Config>>>()
        .ok_or_else(|| error::ErrorInternalServerError("cannot acquire config"))?
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
    let token = authorization_secret(request).unwrap_or_default();
    let path = request.path();

    if request.method() == Method::DELETE {
        let Some(tokens) = config.get_tokens(TokenType::Delete) else {
            return Err(error::ErrorNotFound(""));
        };
        if !tokens.contains(token) {
            return Err(error::ErrorUnauthorized("unauthorized\n"));
        }
        return Ok(RequestAuth {
            principal: None,
            credential_id: None,
            expires_at: None,
            global_delete: true,
            source: CredentialSource::LegacyPublic,
        });
    }

    let protected =
        (request.method() == Method::POST && path == "/") || matches!(path, "/list" | "/version");
    if protected {
        if let Some(tokens) = config.get_tokens(TokenType::Auth) {
            if !tokens.contains(token) {
                return Err(error::ErrorUnauthorized("unauthorized\n"));
            }
        }
    }

    Ok(RequestAuth {
        principal: None,
        credential_id: None,
        expires_at: None,
        global_delete: false,
        source: CredentialSource::LegacyPublic,
    })
}

fn validate_cookie_origin(request: &HttpRequest, runtime: &AuthRuntime) -> Result<(), Error> {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return Ok(());
    }
    let expected = Url::parse(&runtime.server_url).map_err(error::ErrorInternalServerError)?;
    let actual = request
        .headers()
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .ok_or_else(|| error::ErrorForbidden("invalid request origin"))?;
    if expected.scheme() != actual.scheme()
        || expected.host_str() != actual.host_str()
        || expected.port_or_known_default() != actual.port_or_known_default()
    {
        return Err(error::ErrorForbidden("invalid request origin"));
    }
    Ok(())
}

fn authorization_secret(request: &HttpRequest) -> Option<&str> {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.split_whitespace().last().unwrap_or_default())
}

fn unauthorized_request(request: &HttpRequest, runtime: &AuthRuntime) -> Error {
    if is_browser_navigation(request) {
        let return_to = external_return_to(request, runtime);
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", &return_to)
            .finish();
        let response = HttpResponse::Found()
            .append_header((
                "Location",
                format!("{}/auth/login?{query}", runtime.server_url),
            ))
            .finish();
        error::InternalError::from_response("authentication required", response).into()
    } else {
        error::ErrorUnauthorized("unauthorized\n")
    }
}

fn external_return_to(request: &HttpRequest, runtime: &AuthRuntime) -> String {
    let request_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let public_path = public_path_prefix(&runtime.server_url);
    format!("{public_path}{request_path}")
}

fn public_path_prefix(server_url: &str) -> String {
    Url::parse(server_url)
        .ok()
        .map(|url| url.path().trim_end_matches('/').to_string())
        .unwrap_or_default()
}

fn public_cookie_path(server_url: &str) -> String {
    let prefix = public_path_prefix(server_url);
    if prefix.is_empty() {
        String::from("/")
    } else {
        prefix
    }
}

fn is_browser_navigation(request: &HttpRequest) -> bool {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return false;
    }
    request
        .headers()
        .get("Sec-Fetch-Mode")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("navigate"))
        || request
            .headers()
            .get(ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html"))
}

/// Refreshes the browser cookie's client-side expiry after authenticated requests.
pub struct SessionCookieRefresh;

impl<S, B> Transform<S, ServiceRequest> for SessionCookieRefresh
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SessionCookieRefreshMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SessionCookieRefreshMiddleware {
            service: Rc::new(service),
        }))
    }
}

/// Session-cookie refresh middleware implementation.
pub struct SessionCookieRefreshMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SessionCookieRefreshMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(context)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        Box::pin(async move {
            let mut response = service.call(request).await?;
            if response.request().path() != "/auth/logout" {
                let secret = response
                    .request()
                    .extensions()
                    .get::<RequestAuth>()
                    .and_then(|auth| match &auth.source {
                        CredentialSource::Browser { secret } => Some(secret.clone()),
                        _ => None,
                    });
                if let (Some(secret), Some(runtime)) = (
                    secret,
                    response
                        .request()
                        .app_data::<web::Data<AuthRuntime>>()
                        .cloned(),
                ) {
                    response
                        .response_mut()
                        .add_cookie(&runtime.session_cookie(secret))
                        .map_err(error::ErrorInternalServerError)?;
                }
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn extracts_legacy_and_bearer_secrets() {
        let raw = TestRequest::default()
            .insert_header((AUTHORIZATION, "legacy-token"))
            .to_http_request();
        assert_eq!(authorization_secret(&raw), Some("legacy-token"));

        let bearer = TestRequest::default()
            .insert_header((AUTHORIZATION, "Bearer api-token"))
            .to_http_request();
        assert_eq!(authorization_secret(&bearer), Some("api-token"));
    }

    #[test]
    fn detects_browser_navigation() {
        let request = TestRequest::get()
            .insert_header(("Sec-Fetch-Mode", "navigate"))
            .to_http_request();
        assert!(is_browser_navigation(&request));
        let request = TestRequest::post()
            .insert_header((ACCEPT, "text/html"))
            .to_http_request();
        assert!(!is_browser_navigation(&request));
    }

    #[test]
    fn preserves_public_path_prefix_for_post_login_redirects() {
        assert_eq!(public_path_prefix("https://paste.example"), "");
        assert_eq!(public_path_prefix("https://paste.example/root/"), "/root");
        assert_eq!(public_cookie_path("https://paste.example"), "/");
        assert_eq!(public_cookie_path("https://paste.example/root/"), "/root");
    }
}
