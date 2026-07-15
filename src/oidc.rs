use base64::Engine;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_json::{Map, Value};
use std::error::Error as StdError;
use std::fmt;
use std::sync::RwLock;
use std::time::Duration;

const OIDC_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const USERINFO_BODY_LIMIT: usize = 1024 * 1024;

/// OIDC authorization request values that must survive the provider redirect.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// URL to redirect the browser to.
    pub url: String,
    /// OAuth CSRF state.
    pub state: String,
    /// OpenID Connect nonce.
    pub nonce: String,
    /// PKCE verifier paired with the authorization request's challenge.
    pub pkce_verifier: String,
}

/// Identity extracted from a verified OpenID Connect ID token.
#[derive(Clone, Debug)]
pub struct OidcIdentity {
    /// Verified issuer URL.
    pub issuer: String,
    /// Stable provider subject.
    pub subject: String,
    /// Optional e-mail claim.
    pub email: Option<String>,
    /// Optional display-name claim.
    pub display_name: Option<String>,
    /// All ID-token and UserInfo claims used by authorization rules.
    pub claims: Map<String, Value>,
}

/// Error returned by OIDC discovery and login completion.
#[derive(Debug)]
pub struct OidcError(String);

impl OidcError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for OidcError {}

/// Discovered OpenID Connect client configuration.
pub struct OidcClient {
    metadata: RwLock<CoreProviderMetadata>,
    issuer_url: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    scopes: Vec<Scope>,
    http_client: reqwest::Client,
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcClient")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

impl OidcClient {
    /// Discovers provider metadata and constructs a client.
    pub async fn discover(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        scopes: Vec<String>,
    ) -> Result<Self, OidcError> {
        let issuer_url = IssuerUrl::new(issuer_url)
            .map_err(|error| OidcError::new(format!("invalid OIDC issuer URL: {error}")))?;
        let redirect_url = RedirectUrl::new(redirect_url)
            .map_err(|error| OidcError::new(format!("invalid OIDC redirect URL: {error}")))?;
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(OIDC_HTTP_TIMEOUT)
            .build()
            .map_err(|error| OidcError::new(format!("cannot create OIDC HTTP client: {error}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &http_client)
            .await
            .map_err(|error| OidcError::new(format!("OIDC discovery failed: {error}")))?;
        let mut scopes: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();
        if !scopes.iter().any(|scope| scope.as_ref() == "openid") {
            scopes.insert(0, Scope::new("openid".to_string()));
        }

        Ok(Self {
            metadata: RwLock::new(metadata),
            issuer_url,
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            redirect_url,
            scopes,
            http_client,
        })
    }

    /// Starts an authorization-code flow using PKCE.
    pub fn authorization_request(&self) -> Result<AuthorizationRequest, OidcError> {
        let metadata = self
            .metadata
            .read()
            .map_err(|_| OidcError::new("cannot acquire OIDC provider metadata"))?
            .clone();
        let client = CoreClient::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            if scope.as_ref() != "openid" {
                request = request.add_scope(scope.clone());
            }
        }
        let (url, state, nonce) = request.url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state: state.secret().to_string(),
            nonce: nonce.secret().to_string(),
            pkce_verifier: verifier.secret().to_string(),
        })
    }

    /// Exchanges an authorization code and verifies the returned identity.
    pub async fn complete_login(
        &self,
        code: String,
        nonce: String,
        pkce_verifier: String,
    ) -> Result<OidcIdentity, OidcError> {
        let metadata = self
            .metadata
            .read()
            .map_err(|_| OidcError::new("cannot acquire OIDC provider metadata"))?
            .clone();
        let client = CoreClient::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone());
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|error| OidcError::new(format!("cannot create OIDC token request: {error}")))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|error| OidcError::new(format!("OIDC token exchange failed: {error}")))?;
        let id_token = token_response
            .id_token()
            .ok_or_else(|| OidcError::new("OIDC provider did not return an ID token"))?;
        let nonce = Nonce::new(nonce);

        let verified_claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
            Ok(claims) => claims.clone(),
            Err(first_error) => {
                let refreshed = CoreProviderMetadata::discover_async(
                    self.issuer_url.clone(),
                    &self.http_client,
                )
                .await
                .map_err(|error| {
                    OidcError::new(format!(
                        "ID token verification failed ({first_error}); provider refresh failed: {error}"
                    ))
                })?;
                let refreshed_client = CoreClient::from_provider_metadata(
                    refreshed.clone(),
                    self.client_id.clone(),
                    Some(self.client_secret.clone()),
                )
                .set_redirect_uri(self.redirect_url.clone());
                let claims = id_token
                    .claims(&refreshed_client.id_token_verifier(), &nonce)
                    .map_err(|error| {
                        OidcError::new(format!("ID token verification failed: {error}"))
                    })?;
                *self
                    .metadata
                    .write()
                    .map_err(|_| OidcError::new("cannot update OIDC provider metadata"))? =
                    refreshed;
                claims.clone()
            }
        };

        if let Some(expected_hash) = verified_claims.access_token_hash() {
            let verifier_metadata = self
                .metadata
                .read()
                .map_err(|_| OidcError::new("cannot acquire OIDC provider metadata"))?
                .clone();
            let verifier_client = CoreClient::from_provider_metadata(
                verifier_metadata,
                self.client_id.clone(),
                Some(self.client_secret.clone()),
            )
            .set_redirect_uri(self.redirect_url.clone());
            let verifier = verifier_client.id_token_verifier();
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg().map_err(|error| {
                    OidcError::new(format!("invalid signing algorithm: {error}"))
                })?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|error| OidcError::new(format!("invalid signing key: {error}")))?,
            )
            .map_err(|error| OidcError::new(format!("cannot verify access-token hash: {error}")))?;
            if actual_hash != *expected_hash {
                return Err(OidcError::new("OIDC access-token hash mismatch"));
            }
        }

        let mut claims = decode_claims(&id_token.to_string())?;
        let userinfo_endpoint = {
            self.metadata
                .read()
                .map_err(|_| OidcError::new("cannot acquire OIDC provider metadata"))?
                .userinfo_endpoint()
                .cloned()
        };
        if let Some(endpoint) = userinfo_endpoint {
            if let Ok(mut user_info) = self
                .http_client
                .get(endpoint.as_str())
                .bearer_auth(token_response.access_token().secret())
                .send()
                .await
            {
                if user_info.status().is_success() {
                    let mut body = Vec::new();
                    let mut valid_body = true;
                    loop {
                        match user_info.chunk().await {
                            Ok(Some(chunk))
                                if body.len().saturating_add(chunk.len())
                                    <= USERINFO_BODY_LIMIT =>
                            {
                                body.extend_from_slice(&chunk);
                            }
                            Ok(None) => break,
                            Ok(Some(_)) | Err(_) => {
                                valid_body = false;
                                break;
                            }
                        }
                    }
                    if valid_body {
                        if let Ok(user_info_claims) =
                            serde_json::from_slice::<Map<String, Value>>(&body)
                        {
                            if user_info_claims.get("sub").and_then(Value::as_str)
                                == Some(verified_claims.subject().as_str())
                            {
                                claims.extend(user_info_claims);
                            }
                        }
                    }
                }
            }
        }

        identity_from_claims(verified_claims, claims)
    }
}

fn identity_from_claims(
    verified_claims: openidconnect::core::CoreIdTokenClaims,
    claims: Map<String, Value>,
) -> Result<OidcIdentity, OidcError> {
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
    let display_name = claims
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(OidcIdentity {
        issuer: verified_claims.issuer().as_str().to_string(),
        subject: verified_claims.subject().as_str().to_string(),
        email,
        display_name,
        claims,
    })
}

fn decode_claims(id_token: &str) -> Result<Map<String, Value>, OidcError> {
    let encoded_payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| OidcError::new("OIDC ID token has an invalid JWT shape"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|error| OidcError::new(format!("cannot decode OIDC ID token: {error}")))?;
    serde_json::from_slice::<Map<String, Value>>(&payload)
        .map_err(|error| OidcError::new(format!("cannot parse OIDC ID-token claims: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_jwt_claims() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"user-1","groups":["paste-users"]}"#);
        let claims = decode_claims(&format!("header.{payload}.signature")).expect("valid claims");
        assert_eq!(claims.get("sub").and_then(Value::as_str), Some("user-1"));
        assert_eq!(
            claims
                .get("groups")
                .and_then(Value::as_array)
                .and_then(|groups| groups.first())
                .and_then(Value::as_str),
            Some("paste-users")
        );
    }

    #[test]
    fn rejects_invalid_jwt_shape() {
        assert!(decode_claims("not-a-jwt").is_err());
    }
}
