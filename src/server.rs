use crate::auth::{AuthRuntime, CredentialSource, RequestAuth, SessionCookieRefresh};
use crate::config::{Config, LandingPageConfig};
use crate::file::Directory;
use crate::header::{self, ContentDisposition};
use crate::mime as mime_util;
use crate::paste::{Paste, PasteType, PASTE_VARIANTS_LIST};
use crate::store::{NewPaste, PasteInsert, PasteRecord, StoreError};
use crate::util::{self, safe_path_join};
use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::{delete, error, get, post, route, web, Error, HttpRequest, HttpResponse};
use awc::error::HeaderValue;
use awc::http::header::{CONTENT_SECURITY_POLICY, X_CONTENT_TYPE_OPTIONS};
use awc::Client;
use base64::Engine;
use byte_unit::{Byte, UnitType};
use futures_util::stream::StreamExt;
use mime::TEXT_PLAIN_UTF_8;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, UNIX_EPOCH};
use uts2ts;

/// Extract password from Authorization header.
///
/// Supports Basic Auth (`Basic base64(user:pass)`) and Bearer tokens (`Bearer <token>`).
fn extract_password_from_auth(auth_header: &str) -> Option<String> {
    if let Some(basic) = auth_header.strip_prefix("Basic ") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(basic)
            .ok()?;
        let creds = String::from_utf8(bytes).ok()?;
        creds.split_once(':').map(|(_, p)| p.to_owned())
    } else {
        auth_header
            .strip_prefix("Bearer ")
            .map(|bearer| bearer.to_owned())
    }
}

fn extract_protected_password(request: &HttpRequest, auth: &RequestAuth) -> Option<String> {
    if let Some(password) = request
        .headers()
        .get("X-Rustypaste-Password")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        return Some(password.to_string());
    }
    if matches!(
        auth.source,
        CredentialSource::Browser { .. } | CredentialSource::LegacyPublic
    ) {
        request
            .headers()
            .get(actix_web::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(extract_password_from_auth)
    } else {
        None
    }
}

/// Shows the landing page.
#[get("/")]
#[allow(deprecated)]
async fn index(
    _auth: RequestAuth,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let mut config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();
    let redirect = HttpResponse::Found()
        .append_header(("Location", env!("CARGO_PKG_HOMEPAGE")))
        .finish();
    if config.server.landing_page.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.text = config.server.landing_page;
        }
    }
    if config.server.landing_page_content_type.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.content_type = config.server.landing_page_content_type;
        }
    }
    if let Some(mut landing_page) = config.landing_page {
        if let Some(file) = landing_page.file {
            landing_page.text = fs::read_to_string(file).ok();
        }
        match landing_page.text {
            Some(page) => Ok(HttpResponse::Ok()
                .content_type(
                    landing_page
                        .content_type
                        .unwrap_or(TEXT_PLAIN_UTF_8.to_string()),
                )
                .body(page)),
            None => Ok(redirect),
        }
    } else {
        Ok(redirect)
    }
}

/// File serving options (i.e. query parameters).
#[derive(Debug, Deserialize)]
struct ServeOptions {
    /// If set to `true`, change the MIME type to `application/octet-stream` and force downloading
    /// the file.
    download: bool,
}

/// Serves a file from the upload directory.
#[route("/{file}", method = "GET", method = "HEAD")]
async fn serve(
    auth: RequestAuth,
    request: HttpRequest,
    file: web::Path<String>,
    options: Option<web::Query<ServeOptions>>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();
    let (path, paste_type) = if let Some(runtime) = request.app_data::<web::Data<AuthRuntime>>() {
        let records = runtime
            .store
            .find_pastes_by_public_filename(&file)
            .await
            .map_err(error::ErrorInternalServerError)?;
        let record = records
            .into_iter()
            .find(|record| record.storage_path.is_file())
            .ok_or_else(|| error::ErrorNotFound("file is not found or expired :(\n"))?;
        if !record
            .storage_path
            .starts_with(path_clean::PathClean::clean(&config.server.upload_path))
        {
            return Err(error::ErrorInternalServerError(
                "paste metadata points outside the upload directory",
            ));
        }
        (record.storage_path, record.paste_type)
    } else {
        let mut path = util::glob_match_file(safe_path_join(&config.server.upload_path, &*file)?)?;
        let mut paste_type = PasteType::File;
        if !path.exists() || path.is_dir() {
            for type_ in &[
                PasteType::Url,
                PasteType::Oneshot,
                PasteType::OneshotUrl,
                PasteType::ProtectedFile,
            ] {
                let alt_path = safe_path_join(type_.get_path(&config.server.upload_path)?, &*file)?;
                let alt_path = util::glob_match_file(alt_path)?;
                if alt_path.exists()
                    || path.file_name().and_then(|v| v.to_str()) == Some(&type_.get_dir())
                {
                    path = alt_path;
                    paste_type = *type_;
                    break;
                }
            }
        }
        (path, paste_type)
    };
    if !path.is_file() || !path.exists() {
        return Err(error::ErrorNotFound("file is not found or expired :(\n"));
    }

    // Check password protection
    if crate::password::has_password(&path) {
        let password = extract_protected_password(&request, &auth)
            .ok_or_else(|| error::ErrorNotFound("file is not found or expired :(\n"))?;

        if !crate::password::verify_file_password(&path, &password)
            .map_err(|e| error::ErrorInternalServerError(format!("password verification: {e}")))?
        {
            // Same error as missing file (prevents enumeration)
            return Err(error::ErrorNotFound("file is not found or expired :(\n"));
        }
    }

    match paste_type {
        PasteType::File | PasteType::RemoteFile | PasteType::Oneshot | PasteType::ProtectedFile => {
            let should_download = options.map(|v| v.download).unwrap_or(false);

            let mut mime_type = if should_download {
                mime::APPLICATION_OCTET_STREAM
            } else {
                mime_util::get_mime_type(&config.paste.mime_override, file.to_string())
                    .map_err(error::ErrorInternalServerError)?
            };
            if !should_download && is_text_like_mime(&mime_type, &config.paste.text_mime_overrides)
            {
                mime_type = TEXT_PLAIN_UTF_8;
            }
            let mut response = NamedFile::open(&path)?
                .disable_content_disposition()
                .set_content_type(mime_type)
                .prefer_utf8(true)
                .into_response(&request);
            if config.server.hardening.unwrap_or(false) {
                apply_security_headers(&mut response);
            }
            if paste_type.is_oneshot() {
                let consumed_path = path.with_file_name(format!(
                    "{}.{}",
                    file,
                    util::get_system_time()?.as_millis()
                ));
                fs::rename(&path, consumed_path)?;
                delete_metadata_for_path(&request, &path).await?;
            }
            Ok(response)
        }
        PasteType::Url => Ok(HttpResponse::Found()
            .append_header(("Location", fs::read_to_string(&path)?))
            .finish()),
        PasteType::OneshotUrl => {
            let resp = HttpResponse::Found()
                .append_header(("Location", fs::read_to_string(&path)?))
                .finish();
            fs::rename(
                &path,
                path.with_file_name(format!("{}.{}", file, util::get_system_time()?.as_millis())),
            )?;
            delete_metadata_for_path(&request, &path).await?;
            Ok(resp)
        }
    }
}

async fn delete_metadata_for_path(
    request: &HttpRequest,
    path: &std::path::Path,
) -> Result<(), Error> {
    if let Some(runtime) = request.app_data::<web::Data<AuthRuntime>>() {
        runtime
            .store
            .delete_paste_by_storage_path(path)
            .await
            .map_err(error::ErrorInternalServerError)?;
    }
    Ok(())
}

/// Adds security hardening headers to the response.
///
/// Sets `X-Content-Type-Options: nosniff` to prevent MIME sniffing and
/// `Content-Security-Policy: default-src 'none'; sandbox` to restrict
/// script execution and embedding.
fn apply_security_headers(response: &mut HttpResponse) {
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
}

/// Returns `true` if the given MIME type represents text-like content that
/// should be rendered as `text/plain` instead of being downloaded.
///
/// A MIME type is considered text-like if any of the following hold:
/// - Its type is `text` (e.g. `text/html`, `text/x-shellscript`)
/// - It has a `+xml` or `+json` structured syntax suffix
/// - It matches one of the user-configured `overrides`
/// - It is a known text-like `application/` type (e.g. `application/json`, `application/xml`)
fn is_text_like_mime(mime_type: &mime::Mime, overrides: &[String]) -> bool {
    if mime_type.type_() == mime::TEXT {
        return true;
    }
    if let Some(suffix) = mime_type.suffix() {
        if matches!(suffix.as_str(), "xml" | "json") {
            return true;
        }
    }
    let essence = mime_type.essence_str();
    if overrides.iter().any(|v| v.eq_ignore_ascii_case(essence)) {
        return true;
    }
    matches!(
        essence,
        "application/javascript"
            | "application/ecmascript"
            | "application/json"
            | "application/x-www-form-urlencoded"
            | "application/x-javascript"
            | "application/xml"
    )
}

/// Remove a file from the upload directory.
#[delete("/{file}")]
async fn delete(
    auth: RequestAuth,
    request: HttpRequest,
    file: web::Path<String>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();

    if let Some(runtime) = request.app_data::<web::Data<AuthRuntime>>() {
        let records = runtime
            .store
            .find_pastes_by_public_filename(&file)
            .await
            .map_err(error::ErrorInternalServerError)?;
        let Some(record) = records
            .into_iter()
            .find(|record| record.storage_path.is_file())
        else {
            return Err(error::ErrorNotFound("file is not found or expired :(\n"));
        };
        if !can_delete_record(&auth, &record) {
            return Err(error::ErrorForbidden(
                "only the paste owner or an administrator may delete this file\n",
            ));
        }
        if !record
            .storage_path
            .starts_with(path_clean::PathClean::clean(&config.server.upload_path))
        {
            return Err(error::ErrorInternalServerError(
                "paste metadata points outside the upload directory",
            ));
        }
        remove_paste_file(&record.storage_path, &file)?;
        runtime
            .store
            .delete_paste(record.id)
            .await
            .map_err(error::ErrorInternalServerError)?;
        return Ok(HttpResponse::Ok().body(String::from("file deleted\n")));
    }

    let mut path = util::glob_match_file(safe_path_join(&config.server.upload_path, &*file)?)?;
    if !path.is_file() || !path.exists() {
        let protected_path = safe_path_join(
            PasteType::ProtectedFile.get_path(&config.server.upload_path)?,
            &*file,
        )?;
        path = util::glob_match_file(protected_path)?;
    }
    if !path.is_file() || !path.exists() {
        return Err(error::ErrorNotFound("file is not found or expired :(\n"));
    }

    remove_paste_file(&path, &file)?;
    Ok(HttpResponse::Ok().body(String::from("file deleted\n")))
}

fn can_delete_record(auth: &RequestAuth, record: &PasteRecord) -> bool {
    auth.global_delete || record.owner_principal_id == auth.principal_id()
}

fn remove_paste_file(path: &std::path::Path, public_filename: &str) -> Result<(), Error> {
    // Delete content first, then its password sidecar to avoid an unprotected window.
    match fs::remove_file(path) {
        Ok(_) => {
            info!("deleted file: {:?}", public_filename);
            crate::password::delete_password_file(path).ok();
            Ok(())
        }
        Err(error_value) => {
            error!("cannot delete file: {}", error_value);
            Err(error::ErrorInternalServerError("cannot delete file"))
        }
    }
}

/// Expose version endpoint
#[get("/version")]
async fn version(
    _auth: RequestAuth,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
    if !config.server.expose_version.unwrap_or(false) {
        warn!("server is not configured to expose version endpoint");
        Err(error::ErrorNotFound(""))?;
    }

    let version = env!("CARGO_PKG_VERSION");
    Ok(HttpResponse::Ok().body(version.to_owned() + "\n"))
}

/// Handles file upload by processing `multipart/form-data`.
#[post("/")]
async fn upload(
    auth: RequestAuth,
    request: HttpRequest,
    mut payload: Multipart,
    client: web::Data<Client>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let auth_runtime = request.app_data::<web::Data<AuthRuntime>>().cloned();
    let connection = request.connection_info().clone();
    let host = connection.realip_remote_addr().unwrap_or("unknown host");
    let server_url = match config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .server
        .url
        .clone()
    {
        Some(v) => v,
        None => {
            format!("{}://{}", connection.scheme(), connection.host(),)
        }
    };
    let time = util::get_system_time()?;
    let mut expiry_date = header::parse_expiry_date(request.headers(), time)?;
    if expiry_date.is_none() {
        expiry_date = config
            .read()
            .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
            .paste
            .default_expiry
            .and_then(|v| time.checked_add(v).map(|t| t.as_millis()));
    }
    let mut urls: Vec<String> = Vec::new();
    while let Some(item) = payload.next().await {
        let header_filename = header::parse_header_filename(request.headers())?;
        let mut field = item?;
        let content = ContentDisposition::from(
            field
                .content_disposition()
                .ok_or_else(|| {
                    error::ErrorInternalServerError("payload must contain content disposition")
                })?
                .clone(),
        );
        if let Ok(paste_type) = PasteType::try_from(&content) {
            let mut bytes = Vec::<u8>::new();
            while let Some(chunk) = field.next().await {
                bytes.append(&mut chunk?.to_vec());
            }
            if bytes.is_empty() {
                warn!("{} sent zero bytes", host);
                return Err(error::ErrorBadRequest("invalid file size"));
            }
            if paste_type != PasteType::Oneshot
                && paste_type != PasteType::RemoteFile
                && paste_type != PasteType::OneshotUrl
                && paste_type != PasteType::ProtectedFile
                && expiry_date.is_none()
                && !config
                    .read()
                    .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
                    .paste
                    .duplicate_files
                    .unwrap_or(true)
            {
                let bytes_checksum = util::sha256_digest(&*bytes)?;
                if let Some(runtime) = &auth_runtime {
                    let owner = auth
                        .principal_id()
                        .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?;
                    if let Some(record) = runtime
                        .store
                        .find_owner_duplicate(owner, &bytes_checksum)
                        .await
                        .map_err(error::ErrorInternalServerError)?
                    {
                        if record.storage_path.is_file()
                            && is_compatible_duplicate(paste_type, record.paste_type)
                        {
                            urls.push(format!("{}/{}\n", server_url, record.public_filename));
                            continue;
                        }
                        if !record.storage_path.is_file() {
                            runtime
                                .store
                                .delete_paste(record.id)
                                .await
                                .map_err(error::ErrorInternalServerError)?;
                        }
                    }
                } else {
                    let config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
                    if let Some(file) = Directory::try_from(config.server.upload_path.as_path())?
                        .get_file(bytes_checksum)
                    {
                        urls.push(format!(
                            "{}/{}\n",
                            server_url,
                            file.path
                                .file_name()
                                .map(|v| v.to_string_lossy())
                                .unwrap_or_default()
                        ));
                        continue;
                    }
                }
            }
            let mut paste = Paste {
                data: bytes.to_vec(),
                type_: paste_type,
            };
            let result = match paste.type_ {
                PasteType::File | PasteType::Oneshot | PasteType::ProtectedFile => {
                    let config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
                    paste.store_file(
                        content.get_file_name()?,
                        expiry_date,
                        header_filename,
                        &config,
                    )?
                }
                PasteType::RemoteFile => {
                    paste
                        .store_remote_file(expiry_date, header_filename, &client, &config)
                        .await?
                }
                PasteType::Url | PasteType::OneshotUrl => {
                    let config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
                    paste
                        .store_url(expiry_date, header_filename, &config)
                        .map_err(|store_error| {
                            if store_error.kind() == std::io::ErrorKind::AlreadyExists {
                                error::ErrorConflict("file already exists\n")
                            } else {
                                store_error.into()
                            }
                        })?
                }
            };

            let stored_metadata = (|| -> Result<(String, u64), Error> {
                if matches!(paste_type, PasteType::Url | PasteType::OneshotUrl) {
                    let stored_data = fs::read(&result.storage_path)?;
                    Ok((
                        util::sha256_digest(&*stored_data)?,
                        u64::try_from(stored_data.len()).map_err(|_| {
                            error::ErrorInternalServerError("paste size is too large")
                        })?,
                    ))
                } else {
                    Ok((
                        util::sha256_digest(&*paste.data)?,
                        u64::try_from(paste.data.len()).map_err(|_| {
                            error::ErrorInternalServerError("paste size is too large")
                        })?,
                    ))
                }
            })();
            let (content_hash, stored_size_bytes) = match stored_metadata {
                Ok(metadata) => metadata,
                Err(metadata_error) => {
                    remove_new_upload(&result.storage_path);
                    return Err(metadata_error);
                }
            };
            if paste_type == PasteType::RemoteFile
                && expiry_date.is_none()
                && !config
                    .read()
                    .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
                    .paste
                    .duplicate_files
                    .unwrap_or(true)
            {
                if let Some(runtime) = &auth_runtime {
                    let owner = auth
                        .principal_id()
                        .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?;
                    if let Some(record) = runtime
                        .store
                        .find_owner_duplicate(owner, &content_hash)
                        .await
                        .map_err(error::ErrorInternalServerError)?
                    {
                        if record.storage_path.is_file()
                            && is_compatible_duplicate(paste_type, record.paste_type)
                        {
                            remove_new_upload(&result.storage_path);
                            urls.push(format!("{}/{}\n", server_url, record.public_filename));
                            continue;
                        }
                        if !record.storage_path.is_file() {
                            runtime
                                .store
                                .delete_paste(record.id)
                                .await
                                .map_err(error::ErrorInternalServerError)?;
                        }
                    }
                }
            }

            if let Some(runtime) = &auth_runtime {
                let owner = auth
                    .principal_id()
                    .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?;
                let deduplicate = expiry_date.is_none()
                    && matches!(
                        paste_type,
                        PasteType::File | PasteType::RemoteFile | PasteType::Url
                    )
                    && !config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
                        .paste
                        .duplicate_files
                        .unwrap_or(true);
                let new_paste = NewPaste {
                    owner_principal_id: Some(owner),
                    public_filename: result.filename.clone(),
                    storage_path: result.storage_path.clone(),
                    paste_type,
                    created_at: i64::try_from(time.as_secs()).map_err(|_| {
                        error::ErrorInternalServerError("paste creation time is too large")
                    })?,
                    size_bytes: stored_size_bytes,
                    expires_at: expiry_seconds(expiry_date)?,
                    content_hash,
                };
                match persist_paste_metadata(runtime, &new_paste, deduplicate).await {
                    Ok(Some(existing)) => {
                        remove_new_upload(&result.storage_path);
                        urls.push(format!("{}/{}\n", server_url, existing.public_filename));
                        continue;
                    }
                    Ok(None) => {}
                    Err(store_error) => {
                        remove_new_upload(&result.storage_path);
                        return Err(store_error);
                    }
                }
            }

            let mut file_name = result.filename;
            let password = result.password;

            info!(
                "{} ({}) is uploaded from {}",
                file_name,
                Byte::from_u128(paste.data.len() as u128)
                    .unwrap_or_default()
                    .get_appropriate_unit(UnitType::Decimal),
                host
            );
            let config = config
                .read()
                .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
            if let Some(handle_spaces_config) = config.server.handle_spaces {
                file_name = handle_spaces_config.process_filename(&file_name);
            }
            if let Some(pwd) = password {
                urls.push(format!("{server_url}/{file_name}\nPassword: {pwd}\n"));
            } else {
                urls.push(format!("{server_url}/{file_name}\n"));
            }
        } else {
            warn!("{} sent an invalid form field", host);
            return Err(error::ErrorBadRequest("invalid form field"));
        }
    }
    Ok(HttpResponse::Ok().body(urls.join("")))
}

async fn persist_paste_metadata(
    runtime: &AuthRuntime,
    paste: &NewPaste,
    deduplicate: bool,
) -> Result<Option<PasteRecord>, Error> {
    if !deduplicate {
        runtime
            .store
            .insert_paste(paste)
            .await
            .map_err(map_paste_store_error)?;
        return Ok(None);
    }

    // A stale metadata row may win the unique-key race after the optimistic
    // filesystem check. Remove it and retry without discarding this upload.
    for _ in 0..3 {
        match runtime.store.insert_paste_deduplicated(paste).await {
            Ok(PasteInsert::Inserted(_)) => return Ok(None),
            Ok(PasteInsert::Duplicate(existing)) if existing.storage_path.is_file() => {
                return Ok(Some(existing));
            }
            Ok(PasteInsert::Duplicate(existing)) => {
                runtime
                    .store
                    .delete_paste(existing.id)
                    .await
                    .map_err(error::ErrorInternalServerError)?;
            }
            Err(store_error) => {
                return Err(map_paste_store_error(store_error));
            }
        }
    }

    Err(error::ErrorInternalServerError(
        "cannot persist paste ownership after removing stale duplicate metadata",
    ))
}

fn map_paste_store_error(store_error: StoreError) -> Error {
    match store_error {
        StoreError::PublicFilenameConflict(_) => error::ErrorConflict("file already exists\n"),
        other => {
            error::ErrorInternalServerError(format!("cannot persist paste ownership: {other}"))
        }
    }
}

fn expiry_seconds(expiry_millis: Option<u128>) -> Result<Option<i64>, Error> {
    expiry_millis
        .map(|value| {
            value
                .checked_add(999)
                .ok_or_else(|| error::ErrorInternalServerError("paste expiry is too large"))
                .and_then(|value| {
                    i64::try_from(value / 1000)
                        .map_err(|_| error::ErrorInternalServerError("paste expiry is too large"))
                })
        })
        .transpose()
}

fn is_compatible_duplicate(requested: PasteType, existing: PasteType) -> bool {
    matches!(
        (requested, existing),
        (
            PasteType::File | PasteType::RemoteFile,
            PasteType::File | PasteType::RemoteFile
        ) | (PasteType::Url, PasteType::Url)
    )
}

fn remove_new_upload(path: &std::path::Path) {
    if let Err(error_value) = fs::remove_file(path) {
        error!(
            "cannot roll back uploaded file {}: {}",
            path.display(),
            error_value
        );
    }
    crate::password::delete_password_file(path).ok();
}

/// File entry item for list endpoint.
#[derive(Serialize, Deserialize)]
pub struct ListItem {
    /// Uploaded file name.
    pub file_name: PathBuf,
    /// Size of the file in bytes.
    pub file_size: Option<u64>,
    /// Item type
    pub item_type: PasteType,
    /// ISO8601 formatted date-time of the moment the file was created (uploaded).
    pub creation_date_utc: Option<String>,
    /// ISO8601 formatted date-time string of the expiration timestamp if one exists for this file.
    pub expires_at_utc: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListOptions {
    scope: Option<String>,
}

/// Returns the list of files.
#[get("/list")]
async fn list(
    auth: RequestAuth,
    request: HttpRequest,
    options: web::Query<ListOptions>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();
    if !config.server.expose_list.unwrap_or(false) {
        warn!("server is not configured to expose list endpoint");
        Err(error::ErrorNotFound(""))?;
    }

    if let Some(runtime) = request.app_data::<web::Data<AuthRuntime>>() {
        let records = match options.scope.as_deref() {
            None | Some("own") => {
                runtime
                    .store
                    .list_owner_pastes(
                        auth.principal_id()
                            .ok_or_else(|| error::ErrorUnauthorized("unauthorized\n"))?,
                    )
                    .await
            }
            Some("all") if auth.is_admin() => runtime.store.list_all_pastes().await,
            Some("all") => {
                return Err(error::ErrorForbidden(
                    "administrator access is required for scope=all\n",
                ));
            }
            Some(_) => return Err(error::ErrorBadRequest("scope must be own or all\n")),
        }
        .map_err(error::ErrorInternalServerError)?;
        let entries = records
            .into_iter()
            .filter(|record| record.storage_path.is_file())
            .map(list_item_from_record)
            .collect::<Vec<_>>();
        return Ok(HttpResponse::Ok().json(entries));
    }

    let get_item_list = |item_type: PasteType| -> Result<Vec<ListItem>, Error> {
        let dir = item_type.get_path(&config.server.upload_path)?;

        //FIX: When running some tests (e.g. test_list) other folders than "root" does not exists
        if !fs::exists(&dir).unwrap_or(false) {
            return Ok(Vec::default());
        }
        Ok(fs::read_dir(dir.as_path())?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let metadata = match e.metadata() {
                        Ok(metadata) => {
                            if metadata.is_dir() {
                                return None;
                            }
                            metadata
                        }
                        Err(e) => {
                            error!("failed to read metadata: {e}");
                            return None;
                        }
                    };
                    let mut file_name = PathBuf::from(e.file_name());

                    let creation_date_utc = metadata.created().ok().map(|v| {
                        let millis = v
                            .duration_since(UNIX_EPOCH)
                            .expect("Time since UNIX epoch should be valid.")
                            .as_millis();
                        uts2ts::uts2ts(
                            i64::try_from(millis)
                                .expect("UNIX time should be smaller than i64::MAX")
                                / 1000,
                        )
                        .as_string()
                    });

                    let expires_at_utc = if let Some(expiration) = file_name
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .and_then(|v| v.parse::<i64>().ok())
                    {
                        file_name.set_extension("");
                        if util::get_system_time().ok()?
                            > Duration::from_millis(expiration.try_into().ok()?)
                        {
                            return None;
                        }
                        Some(uts2ts::uts2ts(expiration / 1000).as_string())
                    } else {
                        None
                    };
                    Some(ListItem {
                        file_name,
                        file_size: match item_type {
                            PasteType::File | PasteType::Oneshot => Some(metadata.len()),
                            _ => None,
                        },
                        item_type,
                        creation_date_utc,
                        expires_at_utc,
                    })
                })
            })
            .collect())
    };

    let entries: Vec<ListItem> = PASTE_VARIANTS_LIST
        .iter()
        .map(|variant| get_item_list(*variant))
        .collect::<Result<Vec<Vec<ListItem>>, Error>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(HttpResponse::Ok().json(entries))
}

fn list_item_from_record(record: PasteRecord) -> ListItem {
    ListItem {
        file_name: PathBuf::from(record.public_filename),
        file_size: match record.paste_type {
            PasteType::File
            | PasteType::RemoteFile
            | PasteType::Oneshot
            | PasteType::ProtectedFile => Some(record.size_bytes),
            PasteType::Url | PasteType::OneshotUrl => None,
        },
        item_type: record.paste_type,
        creation_date_utc: Some(uts2ts::uts2ts(record.created_at).as_string()),
        expires_at_utc: record
            .expires_at
            .map(|expires_at| uts2ts::uts2ts(expires_at).as_string()),
    }
}

async fn method_not_allowed(_auth: RequestAuth) -> HttpResponse {
    HttpResponse::MethodNotAllowed().finish()
}

/// Configures the server routes.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .service(index)
            .service(version)
            .service(list)
            .service(serve)
            .service(upload)
            .service(delete)
            .route("", web::head().to(method_not_allowed))
            .wrap(SessionCookieRefresh),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LandingPageConfig;
    use crate::middleware::ContentLengthLimiter;
    use crate::random::{RandomURLConfig, RandomURLType};
    use actix_web::body::MessageBody;
    use actix_web::body::{BodySize, BoxBody};
    use actix_web::error::Error;
    use actix_web::http::header::AUTHORIZATION;
    use actix_web::http::{header, StatusCode};
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use awc::ClientBuilder;
    use glob::glob;
    use std::fs::File;
    use std::io::Write;

    fn request_auth(source: CredentialSource) -> RequestAuth {
        RequestAuth {
            principal: None,
            credential_id: None,
            expires_at: None,
            global_delete: false,
            source,
        }
    }

    #[test]
    fn protected_password_uses_separate_header_for_api_tokens() {
        let api_auth = request_auth(CredentialSource::Api {
            secret: String::from("api-token"),
        });
        let request = TestRequest::get()
            .insert_header((AUTHORIZATION, "Bearer api-token"))
            .to_http_request();
        assert_eq!(None, extract_protected_password(&request, &api_auth));

        let request = TestRequest::get()
            .insert_header((AUTHORIZATION, "Bearer api-token"))
            .insert_header(("X-Rustypaste-Password", "paste-password"))
            .to_http_request();
        assert_eq!(
            Some(String::from("paste-password")),
            extract_protected_password(&request, &api_auth)
        );

        let browser_auth = request_auth(CredentialSource::Browser {
            secret: String::from("session"),
        });
        let request = TestRequest::get()
            .insert_header((AUTHORIZATION, "Bearer paste-password"))
            .to_http_request();
        assert_eq!(
            Some(String::from("paste-password")),
            extract_protected_password(&request, &browser_auth)
        );
    }

    #[test]
    fn duplicate_types_preserve_paste_semantics() {
        assert!(is_compatible_duplicate(
            PasteType::RemoteFile,
            PasteType::File
        ));
        assert!(is_compatible_duplicate(PasteType::Url, PasteType::Url));
        assert!(!is_compatible_duplicate(
            PasteType::File,
            PasteType::ProtectedFile
        ));
        assert!(!is_compatible_duplicate(PasteType::Url, PasteType::File));
    }
    use std::path::PathBuf;
    use std::str;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    fn get_multipart_request(data: &str, name: &str, filename: &str) -> TestRequest {
        let multipart_data = format!(
            "\r\n\
             --multipart_bound\r\n\
             Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n\
             {}\r\n\
             --multipart_bound--\r\n",
            name,
            filename,
            data.len(),
            data,
        );
        TestRequest::post()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("multipart/mixed; boundary=\"multipart_bound\""),
            ))
            .insert_header((
                header::CONTENT_LENGTH,
                header::HeaderValue::from_str(&data.len().to_string())
                    .expect("cannot create header value"),
            ))
            .set_payload(multipart_data)
    }

    async fn assert_body(body: BoxBody, expected: &str) -> Result<(), Error> {
        if let BodySize::Sized(size) = body.size() {
            assert_eq!(size, expected.len() as u64);
            let body_bytes = actix_web::body::to_bytes(body).await?;
            let body_text = str::from_utf8(&body_bytes)?;
            assert_eq!(expected, body_text);
            Ok(())
        } else {
            Err(error::ErrorInternalServerError("unexpected body type"))
        }
    }

    #[test]
    fn test_is_text_like_mime_defaults() {
        let overrides = Vec::<String>::new();
        assert!(is_text_like_mime(
            &mime::Mime::from_str("text/plain").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/atom+xml").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/problem+json").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("image/svg+xml").expect("invalid mime"),
            &overrides
        ));
        assert!(!is_text_like_mime(
            &mime::Mime::from_str("application/octet-stream").expect("invalid mime"),
            &overrides
        ));
    }

    #[test]
    fn test_is_text_like_mime_overrides() {
        let overrides = vec![
            String::from("application/toml"),
            String::from("application/x-yaml"),
        ];
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/toml").expect("invalid mime"),
            &overrides
        ));
        assert!(is_text_like_mime(
            &mime::Mime::from_str("application/x-yaml").expect("invalid mime"),
            &overrides
        ));
        assert!(!is_text_like_mime(
            &mime::Mime::from_str("application/pdf").expect("invalid mime"),
            &overrides
        ));
    }

    #[actix_web::test]
    async fn test_index() {
        let config = Config::default();
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
    }

    #[actix_web::test]
    async fn test_index_with_landing_page() -> Result<(), Error> {
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_index_with_landing_page_file() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut file = File::create(filename)?;
        file.write_all("landing page from file".as_bytes())?;
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page from file").await?;
        fs::remove_file(filename)?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_index_with_landing_page_file_not_found() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
        Ok(())
    }

    #[actix_web::test]
    async fn test_version_without_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_version_without_config() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_version() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_version = Some(true);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &(env!("CARGO_PKG_VERSION").to_owned() + "\n"),
        )
        .await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_list() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename).to_request(),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.first().expect("json object").file_name,
            PathBuf::from(filename)
        );

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_list_item_type() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        config.server.upload_path = PathBuf::from(test_upload_dir);

        for variant in PASTE_VARIANTS_LIST {
            fs::create_dir_all(
                variant
                    .get_path(&config.server.upload_path)
                    .expect("Bad upload path"),
            )?;
        }

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename).to_request(),
        )
        .await;
        let filename_oneshot = "oneshot.txt";
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "oneshot", filename_oneshot).to_request(),
        )
        .await;
        test::call_service(
            &app,
            get_multipart_request(env!("CARGO_PKG_HOMEPAGE"), "url", "").to_request(),
        )
        .await;
        let filename_oneshot_url = "oneshot_url";
        test::call_service(
            &app,
            get_multipart_request(
                env!("CARGO_PKG_HOMEPAGE"),
                filename_oneshot_url,
                filename_oneshot_url,
            )
            .to_request(),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        assert_eq!(result.len(), 4);

        // Items returned from `/list` endpoint should be returned in this order:
        // 1. PasteType::File
        // 2. PasteType::Oneshot
        // 3. PasteType::Url
        // 4. PasteType::OneshotUrl
        // NOTE: The test won't pass if order in `PASTE_VARIANTS_LIST` changes

        assert_eq!(result[0].file_name, PathBuf::from(filename));
        assert_eq!(result[0].item_type, PasteType::File);

        assert_eq!(result[1].file_name, PathBuf::from(filename_oneshot));
        assert_eq!(result[1].item_type, PasteType::Oneshot);

        assert_eq!(result[2].file_name, PathBuf::from("url"));
        assert_eq!(result[2].item_type, PasteType::Url);

        assert_eq!(result[3].file_name, PathBuf::from(filename_oneshot_url));
        assert_eq!(result[3].item_type, PasteType::OneshotUrl);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_list_expired() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("50ms"),
                ))
                .to_request(),
        )
        .await;

        thread::sleep(Duration::from_millis(500));

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        assert!(result.is_empty());

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_list_excludes_password_files() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload_protected_list";
        // Clean up from any previous test runs
        let _ = fs::remove_dir_all(test_upload_dir);
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        // Create protected subdirectory
        fs::create_dir(PathBuf::from(test_upload_dir).join("protected"))?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "secret.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();

        // Upload a protected file (creates both secret.txt and secret.txt.password in protected/ subdir)
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "protected", filename).to_request(),
        )
        .await;

        // Verify both files exist in protected/ subdirectory
        let main_file = PathBuf::from(test_upload_dir)
            .join("protected")
            .join(filename);
        let password_file = PathBuf::from(test_upload_dir)
            .join("protected")
            .join(format!("{filename}.password"));
        assert!(main_file.exists());
        assert!(password_file.exists());

        // Call /list endpoint (reads root directory only)
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        // Should return 0 files (protected files are in subdirectory, not shown in root listing)
        assert_eq!(result.len(), 0);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let response =
            test::call_service(&app, get_multipart_request("", "", "").to_request()).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_payload_limit() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .wrap(ContentLengthLimiter::new(Byte::from_u64(1)))
                .configure(configure_routes),
        )
        .await;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "test").to_request(),
        )
        .await;
        assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, response.status());
        assert_body(response.into_body().boxed(), "upload limit exceeded").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_delete_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.delete_tokens = Some(["test".to_string()].into());
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;

        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "file deleted\n").await?;

        let path = PathBuf::from(file_name);
        assert!(!path.exists());

        let password_path = PathBuf::from(format!("{file_name}.password"));
        assert!(!password_path.exists(), "password file should be deleted");

        Ok(())
    }

    #[actix_web::test]
    async fn test_delete_protected_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.delete_tokens = Some(["test".to_string()].into());
        config.server.upload_path = env::current_dir()?;

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("cannot get protected file path");
        fs::create_dir_all(&protected_upload_path)?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_protected_delete.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "protected", file_name).to_request(),
        )
        .await;

        let path = protected_upload_path.join(file_name);
        let password_path = protected_upload_path.join(format!("{file_name}.password"));
        assert!(path.exists());
        assert!(password_path.exists());

        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "file deleted\n").await?;

        assert!(!path.exists());
        assert!(
            !password_path.exists(),
            "password file should be deleted with the content file"
        );

        fs::remove_dir(protected_upload_path)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_delete_file_without_token_in_config() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(file_name)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_file_override_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(header_filename)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_same_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::CONFLICT, response.status());
        assert_body(response.into_body(), "file already exists\n").await?;

        fs::remove_file(header_filename)?;

        Ok(())
    }

    #[actix_web::test]
    #[allow(deprecated)]
    async fn test_upload_duplicate_file() -> Result<(), Error> {
        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(&test_upload_dir);
        config.paste.duplicate_files = Some(false);
        config.paste.random_url = Some(RandomURLConfig {
            enabled: Some(true),
            type_: RandomURLType::Alphanumeric,
            ..Default::default()
        });

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let first_body_bytes = actix_web::body::to_bytes(body).await?;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let second_body_bytes = actix_web::body::to_bytes(body).await?;

        assert_eq!(first_body_bytes, second_body_bytes);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_expiring_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("20ms"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        thread::sleep(Duration::from_millis(40));

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(&format!("{file_name}.[0-9]*"))
            .map_err(error::ErrorInternalServerError)?
            .next()
        {
            fs::remove_file(glob_path.map_err(error::ErrorInternalServerError)?)?;
        }

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_remote_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;
        config.server.max_content_length = Byte::from_u128(30000).unwrap_or_default();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(
                    ClientBuilder::new()
                        .timeout(Duration::from_secs(30))
                        .finish(),
                ))
                .configure(configure_routes),
        )
        .await;

        let file_name =
            "rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png";
        let response = test::call_service(
            &app,
            get_multipart_request(
                "https://raw.githubusercontent.com/orhun/rustypaste/refs/heads/master/img/rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png",
                "remote",
                file_name,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body().boxed(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());

        let body = response.into_body();
        let body_bytes = actix_web::body::to_bytes(body).await?;
        assert_eq!(
            "3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f",
            util::sha256_digest(&*body_bytes)?
        );

        fs::remove_file(file_name)?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_remote_file_override_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;
        config.server.max_content_length = Byte::from_u128(30000).unwrap_or_default();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(
                    ClientBuilder::new()
                        .timeout(Duration::from_secs(30))
                        .finish(),
                ))
                .configure(configure_routes),
        )
        .await;

        let file_name = "fn_from_header.txt";
        let response = test::call_service(
            &app,
            get_multipart_request(
                "https://raw.githubusercontent.com/orhun/rustypaste/refs/heads/master/img/rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png",
                "remote",
                file_name,
            )
            .insert_header((
                header::HeaderName::from_static("filename"),
                header::HeaderValue::from_static(file_name),
            ))
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body().boxed(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());

        let body = response.into_body();
        let body_bytes = actix_web::body::to_bytes(body).await?;
        assert_eq!(
            "3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f",
            util::sha256_digest(&*body_bytes)?
        );

        fs::remove_file(file_name)?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let url_upload_path = PasteType::Url
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = test::call_service(
            &app,
            get_multipart_request(env!("CARGO_PKG_HOMEPAGE"), "url", "").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "http://localhost:8080/url\n").await?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        fs::remove_file(url_upload_path.join("url"))?;
        fs::remove_dir(url_upload_path)?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_oneshot() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let oneshot_upload_path = PasteType::Oneshot
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&oneshot_upload_path)?;

        let file_name = "oneshot.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "oneshot", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(
            &oneshot_upload_path
                .join(format!("{file_name}.[0-9]*"))
                .to_string_lossy(),
        )
        .map_err(error::ErrorInternalServerError)?
        .next()
        {
            fs::remove_file(glob_path.map_err(error::ErrorInternalServerError)?)?;
        }
        fs::remove_dir(oneshot_upload_path)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_oneshot_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let oneshot_url_suffix = "oneshot_url";

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let url_upload_path = PasteType::OneshotUrl
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = test::call_service(
            &app,
            get_multipart_request(
                env!("CARGO_PKG_HOMEPAGE"),
                oneshot_url_suffix,
                oneshot_url_suffix,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{oneshot_url_suffix}\n"),
        )
        .await?;

        // Make the oneshot_url request, ensure it is found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        // Make the same request again, and ensure that the oneshot_url is not found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Cleanup
        fs::remove_dir_all(url_upload_path)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_protected_file() -> Result<(), Error> {
        let test_upload_dir = "test_upload_protected";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&protected_upload_path)?;

        let file_name = "protected.txt";
        let file_content = "secret content";

        // Upload protected file
        let response = test::call_service(
            &app,
            get_multipart_request(file_content, "protected", file_name).to_request(),
        )
        .await;

        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let body_bytes = actix_web::body::to_bytes(body).await?;
        let body_text = str::from_utf8(&body_bytes)?;

        // Extract URL and password from response
        let lines: Vec<&str> = body_text.lines().collect();
        assert_eq!(2, lines.len(), "Expected URL and password in response");
        assert!(
            lines[0].contains(file_name),
            "First line should contain URL"
        );
        assert!(
            lines[1].starts_with("Password: "),
            "Second line should contain password"
        );

        let password = lines[1]
            .strip_prefix("Password: ")
            .expect("Failed to extract password")
            .to_string();

        // Access without authorization header -> 404
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with wrong password (Bearer) -> 404
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, "Bearer wrongpassword"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with wrong password (Basic Auth) -> 404
        let wrong_basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"user:wrongpassword"
            )
        );
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, wrong_basic))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Access with correct password (Bearer) -> 200
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, format!("Bearer {password}")))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), file_content).await?;

        // Access with correct password (Basic Auth) -> 200
        let correct_basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("user:{password}").as_bytes()
            )
        );
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, correct_basic))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), file_content).await?;

        // Cleanup
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_protected_file_enumeration_prevention() -> Result<(), Error> {
        let test_upload_dir = "test_upload_enum";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let protected_upload_path = PasteType::ProtectedFile
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&protected_upload_path)?;

        // Test that both missing files and protected files return same error code
        // This prevents attackers from enumerating files

        // Request non-existent file -> 404
        let serve_request = TestRequest::get().uri("/nonexistent.txt").to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Upload protected file
        let file_name = "protected_enum.txt";
        let response = test::call_service(
            &app,
            get_multipart_request("content", "protected", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());

        // Request protected file without auth -> 404 (same as non-existent)
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Request protected file with wrong password -> 404 (same as non-existent)
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .insert_header((AUTHORIZATION, "Bearer wrongpassword"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Cleanup
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }
}
