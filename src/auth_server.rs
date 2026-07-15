//! HTTP endpoints for OIDC browser login and browser-assisted CLI authorization.

use crate::auth::{AuthRuntime, RequestAuth, SessionCookieRefresh};
use crate::store::{DevicePoll, Principal, PrincipalKind, StoreError};
use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use actix_web::http::header::LOCATION;
use actix_web::{delete, error, get, post, web, Error, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use subtle::ConstantTimeEq;

const OAUTH_FLOW_LIFETIME: Duration = Duration::from_secs(10 * 60);
const DEVICE_FLOW_LIFETIME: Duration = Duration::from_secs(10 * 60);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const OAUTH_FLOW_COOKIE: &str = "rustypaste_oauth_state";

#[derive(Debug, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DeviceRequest {
    client_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenRequest {
    device_code: String,
}

#[derive(Debug, Serialize)]
struct DeviceTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    credential_id: String,
}

#[derive(Debug, Serialize)]
struct OAuthErrorResponse<'a> {
    error: &'a str,
    error_description: &'a str,
}

#[derive(Debug, Deserialize)]
struct VerifyQuery {
    user_code: String,
}

#[derive(Debug, Deserialize)]
struct VerifyForm {
    user_code: String,
}

#[derive(Debug, Serialize)]
struct IdentityResponse {
    principal_id: i64,
    kind: &'static str,
    issuer: Option<String>,
    subject: Option<String>,
    name: Option<String>,
    email: Option<String>,
    is_admin: bool,
    credential_id: Option<i64>,
    expires_at: Option<i64>,
}

/// Registers authentication endpoints under `/auth`.
pub fn configure_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/auth")
            .service(login)
            .service(callback)
            .service(me)
            .service(logout)
            .service(revoke_token)
            .service(device)
            .service(device_token)
            .service(verify_device)
            .service(approve_device)
            .service(list_principals)
            .service(revoke_principal_credentials)
            .wrap(SessionCookieRefresh),
    );
}

#[get("/login")]
async fn login(
    query: web::Query<LoginQuery>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let return_to = query.return_to.as_deref().unwrap_or("/");
    if return_to.len() > 2048 {
        return Err(error::ErrorBadRequest("return_to is too long"));
    }
    let authorization = runtime
        .oidc
        .authorization_request()
        .map_err(error::ErrorInternalServerError)?;
    runtime
        .store
        .store_oauth_flow(
            &authorization.state,
            &authorization.pkce_verifier,
            &authorization.nonce,
            return_to,
            OAUTH_FLOW_LIFETIME,
        )
        .await
        .map_err(map_flow_store_error)?;
    let callback_path = oauth_callback_path(&runtime.server_url)?;
    Ok(HttpResponse::Found()
        .append_header((LOCATION, authorization.url))
        .cookie(oauth_flow_cookie(
            &authorization.state,
            runtime.config.secure_cookies,
            &callback_path,
        ))
        .finish())
}

#[get("/callback")]
async fn callback(
    request: HttpRequest,
    query: web::Query<CallbackQuery>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let state = query
        .state
        .as_deref()
        .ok_or_else(|| error::ErrorBadRequest("missing OAuth state"))?;
    let cookie_state = request
        .cookie(OAUTH_FLOW_COOKIE)
        .ok_or_else(|| error::ErrorBadRequest("missing OAuth flow cookie"))?;
    if !bool::from(cookie_state.value().as_bytes().ct_eq(state.as_bytes())) {
        return Err(error::ErrorBadRequest(
            "OAuth state does not match this browser",
        ));
    }
    let callback_path = oauth_callback_path(&runtime.server_url)?;
    if let Some(provider_error) = &query.error {
        let description = query.error_description.as_deref().unwrap_or(provider_error);
        return Ok(HttpResponse::Unauthorized()
            .cookie(removal_oauth_flow_cookie(
                runtime.config.secure_cookies,
                &callback_path,
            ))
            .body(format!("OIDC authorization failed: {description}")));
    }
    let code = query
        .code
        .clone()
        .ok_or_else(|| error::ErrorBadRequest("missing authorization code"))?;
    let flow = runtime
        .store
        .consume_oauth_flow(state)
        .await
        .map_err(error::ErrorInternalServerError)?
        .ok_or_else(|| error::ErrorBadRequest("invalid or expired OAuth state"))?;
    let identity = runtime
        .oidc
        .complete_login(
            code,
            flow.nonce.expose().to_string(),
            flow.code_verifier.expose().to_string(),
        )
        .await
        .map_err(error::ErrorUnauthorized)?;
    if !runtime.config.authorization.allows(&identity.claims) {
        return Err(error::ErrorForbidden(
            "identity does not satisfy the configured authorization claims",
        ));
    }
    let is_admin = runtime.config.authorization.is_admin(&identity.claims);
    let principal = runtime
        .store
        .upsert_oidc_principal(
            &identity.issuer,
            &identity.subject,
            identity.email.as_deref(),
            identity.display_name.as_deref(),
            is_admin,
        )
        .await
        .map_err(error::ErrorInternalServerError)?;
    let session = runtime
        .store
        .create_browser_session(principal.id)
        .await
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Found()
        .append_header((LOCATION, flow.return_to))
        .cookie(runtime.session_cookie(session.secret.expose().to_string()))
        .cookie(removal_oauth_flow_cookie(
            runtime.config.secure_cookies,
            &callback_path,
        ))
        .finish())
}

fn oauth_flow_cookie(state: &str, secure: bool, callback_path: &str) -> Cookie<'static> {
    Cookie::build(OAUTH_FLOW_COOKIE, state.to_string())
        .path(callback_path.to_string())
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(
            i64::try_from(OAUTH_FLOW_LIFETIME.as_secs()).unwrap_or(i64::MAX),
        ))
        .finish()
}

fn removal_oauth_flow_cookie(secure: bool, callback_path: &str) -> Cookie<'static> {
    let mut cookie = oauth_flow_cookie("", secure, callback_path);
    cookie.make_removal();
    cookie
}

fn oauth_callback_path(server_url: &str) -> Result<String, Error> {
    let url = url::Url::parse(server_url).map_err(error::ErrorInternalServerError)?;
    Ok(format!(
        "{}/auth/callback",
        url.path().trim_end_matches('/')
    ))
}

#[get("/me")]
async fn me(auth: RequestAuth) -> Result<HttpResponse, Error> {
    let principal = auth
        .principal
        .as_ref()
        .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?;
    Ok(HttpResponse::Ok().json(identity_response(
        principal,
        auth.credential_id,
        auth.expires_at,
    )))
}

#[post("/logout")]
async fn logout(auth: RequestAuth, runtime: web::Data<AuthRuntime>) -> Result<HttpResponse, Error> {
    if let Some(secret) = auth.browser_secret() {
        runtime
            .store
            .revoke_browser_session(secret)
            .await
            .map_err(error::ErrorInternalServerError)?;
    }
    Ok(HttpResponse::NoContent()
        .cookie(runtime.removal_cookie())
        .finish())
}

#[delete("/token")]
async fn revoke_token(
    auth: RequestAuth,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let secret = auth
        .api_secret()
        .ok_or_else(|| error::ErrorBadRequest("request did not use an API token"))?;
    runtime
        .store
        .revoke_api_token(secret)
        .await
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::NoContent().finish())
}

#[post("/cli/device")]
async fn device(
    request: Option<web::Json<DeviceRequest>>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let client_name = request
        .as_ref()
        .and_then(|request| request.client_name.as_deref())
        .unwrap_or("CLI")
        .trim();
    if client_name.is_empty()
        || client_name.len() > 100
        || client_name.chars().any(char::is_control)
    {
        return Err(error::ErrorBadRequest("invalid client name"));
    }
    let authorization = runtime
        .store
        .start_device_flow(client_name, DEVICE_FLOW_LIFETIME, DEVICE_POLL_INTERVAL)
        .await
        .map_err(map_flow_store_error)?;
    let verification_uri = format!("{}/auth/cli/verify", runtime.server_url);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("user_code", &authorization.user_code)
        .finish();
    Ok(HttpResponse::Ok().json(DeviceResponse {
        device_code: authorization.device_code.expose().to_string(),
        user_code: authorization.user_code,
        verification_uri: verification_uri.clone(),
        verification_uri_complete: format!("{verification_uri}?{query}"),
        expires_in: DEVICE_FLOW_LIFETIME.as_secs(),
        interval: authorization.poll_interval.as_secs(),
    }))
}

#[get("/cli/verify")]
async fn verify_device(
    _auth: RequestAuth,
    query: web::Query<VerifyQuery>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let client_name = runtime
        .store
        .get_device_flow_client_name(&query.user_code)
        .await
        .map_err(error::ErrorInternalServerError)?
        .ok_or_else(|| error::ErrorBadRequest("invalid or expired CLI code"))?;
    let code = html_escape(&query.user_code);
    let client_name = html_escape(&client_name);
    let approve_url = html_escape(&format!("{}/auth/cli/verify", runtime.server_url));
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorize rustypaste CLI</title></head>\
         <body><main><h1>Authorize CLI</h1><p><strong>{client_name}</strong> is requesting access.</p>\
         <p>Confirm code <strong>{code}</strong>.</p>\
         <form action=\"{approve_url}\" method=\"post\"><input type=\"hidden\" name=\"user_code\" value=\"{code}\">\
         <button type=\"submit\">Authorize</button></form></main></body></html>"
    );
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

#[post("/cli/verify")]
async fn approve_device(
    auth: RequestAuth,
    form: web::Form<VerifyForm>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    let principal_id = auth
        .principal_id()
        .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?;
    if !runtime
        .store
        .approve_device_flow(&form.user_code, principal_id)
        .await
        .map_err(error::ErrorInternalServerError)?
    {
        return Err(error::ErrorBadRequest(
            "invalid, expired, or already approved CLI code",
        ));
    }
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<!doctype html><html lang=\"en\"><body><p>CLI authorized. You can close this window.</p></body></html>"))
}

#[post("/cli/token")]
async fn device_token(
    request: web::Json<DeviceTokenRequest>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    match runtime
        .store
        .poll_device_flow(&request.device_code, Some("rustypaste-cli"))
        .await
        .map_err(error::ErrorInternalServerError)?
    {
        DevicePoll::Pending => Ok(oauth_error(
            "authorization_pending",
            "waiting for browser authorization",
        )),
        DevicePoll::SlowDown => Ok(oauth_error(
            "slow_down",
            "polling faster than the advertised interval",
        )),
        DevicePoll::Expired | DevicePoll::Consumed => {
            Ok(oauth_error("expired_token", "CLI login request expired"))
        }
        DevicePoll::Authorized { credential, .. } => {
            let now = unix_seconds()?;
            Ok(HttpResponse::Ok().json(DeviceTokenResponse {
                access_token: credential.secret.expose().to_string(),
                token_type: "Bearer",
                expires_in: u64::try_from(credential.expires_at.saturating_sub(now))
                    .unwrap_or_default(),
                credential_id: credential.id.to_string(),
            }))
        }
    }
}

#[get("/admin/principals")]
async fn list_principals(
    auth: RequestAuth,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    require_admin(&auth)?;
    let principals = runtime
        .store
        .list_principals()
        .await
        .map_err(error::ErrorInternalServerError)?
        .into_iter()
        .map(|principal| identity_response(&principal, None, None))
        .collect::<Vec<_>>();
    Ok(HttpResponse::Ok().json(principals))
}

#[delete("/admin/principals/{id}/credentials")]
async fn revoke_principal_credentials(
    auth: RequestAuth,
    principal_id: web::Path<i64>,
    runtime: web::Data<AuthRuntime>,
) -> Result<HttpResponse, Error> {
    require_admin(&auth)?;
    let revoked = runtime
        .store
        .revoke_principal_credentials(*principal_id)
        .await
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "revoked": revoked })))
}

fn require_admin(auth: &RequestAuth) -> Result<(), Error> {
    if auth.is_admin() {
        Ok(())
    } else {
        Err(error::ErrorForbidden("administrator access required"))
    }
}

fn identity_response(
    principal: &Principal,
    credential_id: Option<i64>,
    expires_at: Option<i64>,
) -> IdentityResponse {
    IdentityResponse {
        principal_id: principal.id,
        kind: match principal.kind {
            PrincipalKind::Oidc => "oidc",
            PrincipalKind::Service => "service",
            PrincipalKind::Legacy => "legacy",
        },
        issuer: principal.issuer.clone(),
        subject: principal.subject.clone(),
        name: principal
            .display_name
            .clone()
            .or_else(|| principal.stable_name.clone()),
        email: principal.email.clone(),
        is_admin: principal.is_admin,
        credential_id,
        expires_at,
    }
}

fn oauth_error(error_code: &'static str, description: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(OAuthErrorResponse {
        error: error_code,
        error_description: description,
    })
}

fn map_flow_store_error(store_error: StoreError) -> Error {
    match store_error {
        StoreError::CapacityExceeded(message) => error::ErrorTooManyRequests(message),
        StoreError::InvalidInput(message) => error::ErrorBadRequest(message),
        other => error::ErrorInternalServerError(other),
    }
}

fn unix_seconds() -> Result<i64, Error> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error::ErrorInternalServerError)?
        .as_secs();
    i64::try_from(seconds).map_err(error::ErrorInternalServerError)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_device_code_for_html() {
        assert_eq!(html_escape("<code&\"'>"), "&lt;code&amp;&quot;&#39;&gt;");
    }

    #[test]
    fn device_and_token_responses_match_the_cli_contract() {
        let device_json = serde_json::to_value(DeviceResponse {
            device_code: String::from("device-secret"),
            user_code: String::from("ABCD-EFGH"),
            verification_uri: String::from("https://paste.example/auth/cli/verify"),
            verification_uri_complete: String::from(
                "https://paste.example/auth/cli/verify?user_code=ABCD-EFGH",
            ),
            expires_in: 600,
            interval: 5,
        })
        .expect("serialize device response");
        assert_eq!(device_json["device_code"], "device-secret");
        assert_eq!(device_json["user_code"], "ABCD-EFGH");
        assert_eq!(device_json["expires_in"], 600);
        assert_eq!(device_json["interval"], 5);

        let token = serde_json::to_value(DeviceTokenResponse {
            access_token: String::from("api-secret"),
            token_type: "Bearer",
            expires_in: 3600,
            credential_id: String::from("42"),
        })
        .expect("serialize token response");
        assert_eq!(token["access_token"], "api-secret");
        assert_eq!(token["token_type"], "Bearer");
        assert_eq!(token["credential_id"], "42");
    }

    #[test]
    fn oauth_flow_cookie_is_short_lived_and_callback_scoped() {
        let cookie = oauth_flow_cookie("state", true, "/paste/auth/callback");
        assert_eq!(cookie.name(), OAUTH_FLOW_COOKIE);
        assert_eq!(cookie.value(), "state");
        assert_eq!(cookie.path(), Some("/paste/auth/callback"));
        assert!(cookie.http_only().unwrap_or(false));
        assert!(cookie.secure().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn scopes_oauth_callback_to_the_public_url_prefix() {
        assert_eq!(
            oauth_callback_path("https://paste.example/root/").expect("callback path"),
            "/root/auth/callback"
        );
        assert_eq!(
            oauth_callback_path("https://paste.example").expect("callback path"),
            "/auth/callback"
        );
    }
}
