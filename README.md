<a href="https://github.com/orhun/rustypaste"><img src="img/rustypaste_logo.png" width="500"></a>

[![GitHub Release](https://img.shields.io/github/v/release/orhun/rustypaste?style=flat&labelColor=823213&color=2c2c2c&logo=GitHub&logoColor=white)](https://github.com/orhun/rustypaste/releases)
[![Crate Release](https://img.shields.io/crates/v/rustypaste?style=flat&labelColor=823213&color=2c2c2c&logo=Rust&logoColor=white)](https://crates.io/crates/rustypaste/)
[![Coverage](https://img.shields.io/codecov/c/gh/orhun/rustypaste?style=flat&labelColor=823213&color=2c2c2c&logo=Codecov&logoColor=white)](https://codecov.io/gh/orhun/rustypaste)
[![Continuous Integration](https://img.shields.io/github/actions/workflow/status/orhun/rustypaste/ci.yml?branch=master&style=flat&labelColor=823213&color=2c2c2c&logo=GitHub%20Actions&logoColor=white)](https://github.com/orhun/rustypaste/actions?query=workflow%3A%22Continuous+Integration%22)
[![Continuous Deployment](https://img.shields.io/github/actions/workflow/status/orhun/rustypaste/cd.yml?style=flat&labelColor=823213&color=2c2c2c&logo=GitHub%20Actions&logoColor=white&label=deploy)](https://github.com/orhun/rustypaste/actions?query=workflow%3A%22Continuous+Deployment%22)
[![Docker Builds](https://img.shields.io/github/actions/workflow/status/orhun/rustypaste/docker.yml?style=flat&labelColor=823213&color=2c2c2c&label=docker&logo=Docker&logoColor=white)](https://hub.docker.com/r/orhunp/rustypaste)
[![Documentation](https://img.shields.io/docsrs/rustypaste?style=flat&labelColor=823213&color=2c2c2c&logo=Rust&logoColor=white)](https://docs.rs/rustypaste/)

**Rustypaste** is a minimal file upload/pastebin service.

```sh
$ echo "some text" > awesome.txt

$ curl -F "file=@awesome.txt" https://paste.site.com
https://paste.site.com/safe-toad.txt

$ curl https://paste.site.com/safe-toad.txt
some text
```

</details>

<details>
  <summary>Table of Contents</summary>

<!-- vim-markdown-toc GFM -->

* [Features](#features)
* [Installation](#installation)
  * [From crates.io](#from-cratesio)
  * [Arch Linux](#arch-linux)
  * [Alpine Linux](#alpine-linux)
  * [FreeBSD](#freebsd)
  * [Binary releases](#binary-releases)
  * [Build from source](#build-from-source)
    * [Feature flags](#feature-flags)
    * [Testing](#testing)
      * [Unit tests](#unit-tests)
      * [Test Fixtures](#test-fixtures)
* [Usage](#usage)
  * [CLI](#cli)
    * [Expiration](#expiration)
    * [One shot files](#one-shot-files)
    * [One shot URLs](#one-shot-urls)
    * [Password-protected files](#password-protected-files)
    * [URL shortening](#url-shortening)
    * [Paste file from remote URL](#paste-file-from-remote-url)
    * [Cleaning up expired files](#cleaning-up-expired-files)
    * [Delete file from server](#delete-file-from-server)
    * [Override the filename](#override-the-filename)
  * [Server](#server)
    * [Authentication](#authentication)
    * [List endpoint](#list-endpoint)
    * [HTML Form](#html-form)
    * [Docker](#docker)
    * [Nginx](#nginx)
  * [Third Party Clients](#third-party-clients)
  * [Contributing](#contributing)
    * [License](#license)

<!-- vim-markdown-toc -->

</details>

## Features

- File upload & URL shortening & upload from URL
  - supports basic HTTP authentication
  - random file names (optional)
    - pet name (e.g. `capital-mosquito.txt`)
    - alphanumeric string (e.g. `yB84D2Dv.txt`)
    - random suffix (e.g. `file.MRV5as.tar.gz`)
  - supports expiring links
    - auto-expiration of files (optional)
    - auto-deletion of expired files (optional)
  - supports one shot links/URLs (can only be viewed once)
  - supports password-protected files
    - auto-generated passwords
    - Argon2id hashing
  - guesses MIME types
    - supports overriding and blacklisting
    - supports forcing to download via `?download=true`
  - no duplicate uploads (optional)
  - listing/deleting files
  - custom landing page
- Single binary
  - [binary releases](https://github.com/orhun/rustypaste/releases)
- Simple configuration
  - supports hot reloading
- Easy to deploy
  - [docker images](https://hub.docker.com/r/orhunp/rustypaste)
  - [appjail images](https://github.com/AppJail-makejails/rustypaste)
- Filesystem-backed paste storage
  - optional SQLite database for OIDC sessions and ownership metadata
- Self-hosted
  - _centralization is bad!_
- Written in Rust
  - _blazingly fast!_

## Installation

<details>
  <summary>Packaging status</summary>

[![Packaging status](https://repology.org/badge/vertical-allrepos/rustypaste.svg)](https://repology.org/project/rustypaste/versions)

</details>

### From crates.io

```sh
cargo install rustypaste
```

### Arch Linux

```sh
pacman -S rustypaste
```

### Alpine Linux

`rustypaste` is available for [Alpine Edge](https://pkgs.alpinelinux.org/packages?name=rustypaste&branch=edge). It can be installed via [apk](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper) after enabling the [community repository](https://wiki.alpinelinux.org/wiki/Repositories).

```sh
apk add rustypaste
```

### FreeBSD

```sh
pkg install rustypaste
```

### Binary releases

See the available binaries on the [releases](https://github.com/orhun/rustypaste/releases/) page.

### Build from source

```sh
git clone https://github.com/orhun/rustypaste.git
cd rustypaste/
cargo build --release
```

#### Feature flags

- `openssl`: use distro OpenSSL (binary size is reduced ~20% in release mode)
- `rustls`: use [rustls](https://github.com/rustls/rustls) (enabled as default)

To enable a feature for build, pass `--features` flag to `cargo build` command.

For example, to reuse the OpenSSL present on a distro already:

```sh
cargo build --release --no-default-features --features openssl
```

#### Testing

##### Unit tests

```sh
cargo test -- --test-threads 1
```

##### Test Fixtures

```sh
./fixtures/test-fixtures.sh
```

## Usage

The standalone command line tool (`rpaste`) is available [here](https://github.com/orhun/rustypaste-cli).

### CLI

```sh
function rpaste() {
  curl -F "file=@$1" -H "Authorization: <auth_token>" "<server_address>"
}
```

**\*** consider reading authorization headers from a file. (e.g. `-H @rpaste_auth`)

```sh
# upload a file
$ rpaste x.txt

# paste from stdin
$ rpaste -
```

#### Expiration

```sh
$ curl -F "file=@x.txt" -H "expire:10min" "<server_address>"
```

supported units:

- `nsec`, `ns`
- `usec`, `us`
- `msec`, `ms`
- `seconds`, `second`, `sec`, `s`
- `minutes`, `minute`, `min`, `m`
- `hours`, `hour`, `hr`, `h`
- `days`, `day`, `d`
- `weeks`, `week`, `w`
- `months`, `month`, `M`
- `years`, `year`, `y`

#### One shot files

```sh
$ curl -F "oneshot=@x.txt" "<server_address>"
```

#### One shot URLs

```sh
$ curl -F "oneshot_url=https://example.com" "<server_address>"
```

#### Password-protected files

Upload a file with auto-generated password:

```sh
$ curl -F "protected=@secret.txt" "<server_address>"
https://paste.site.com/secret.txt
Password: aBcD1234EfGh5678IjKl9012
```

Download with Bearer token:

```sh
$ curl -H "Authorization: Bearer aBcD1234EfGh5678IjKl9012" https://paste.site.com/secret.txt
```

When OIDC is enabled, API requests use the `Authorization` header for the global
API credential. Pass the paste password separately:

```sh
$ curl \
  -H "Authorization: Bearer <api_token>" \
  -H "X-Rustypaste-Password: aBcD1234EfGh5678IjKl9012" \
  https://paste.site.com/secret.txt
```

A browser session can continue to use the existing Basic or Bearer password
forms because the session cookie supplies global authentication.

Or with Basic Auth:

```sh
$ curl -u "user:aBcD1234EfGh5678IjKl9012" https://paste.site.com/secret.txt
```

**Note**: Protected files cannot be combined with other paste types (oneshot, URL). The password is permanently tied to the file and cannot be changed. If the password is lost, the file becomes inaccessible. Password files are deleted automatically when the main file is deleted or expires.

#### URL shortening

```sh
$ curl -F "url=https://example.com/some/long/url" "<server_address>"
```

#### Paste file from remote URL

```sh
$ curl -F "remote=https://example.com/file.png" "<server_address>"
```

#### Cleaning up expired files

Configure `[paste].delete_expired_files` to set an interval for deleting the expired files automatically.

On the other hand, following script can be used as [cron](https://en.wikipedia.org/wiki/Cron) for cleaning up the expired files manually:

```sh
#!/bin/env sh
now=$(date +%s)
find upload/ -maxdepth 2 -type f -iname "*.[0-9]*" |
while read -r filename; do
	[ "$(( ${filename##*.} / 1000 - "${now}" ))" -lt 0 ] && rm -v "${filename}"
done
```

#### Delete file from server

With legacy authentication, set the `delete_tokens` array in [config.toml](./config.toml) to activate the [`DELETE`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/DELETE) endpoint and secure it with one (or more) auth token(s).

```sh
$ curl -H "Authorization: <auth_token>" -X DELETE "<server_address>/file.txt"
```

> Without `[auth]`, the `DELETE` endpoint will not be exposed and will return a
> `404` error if `delete_tokens` are not set. With OIDC enabled, owners can
> delete their own pastes and administrators can delete any paste without a
> legacy delete token.

#### Override the filename

When using the `random_url` config option, or when pasting a file [from remote URL](#paste-file-from-remote-url), rustypaste automatically selects a filename.

This can be overridden by sending a header called `filename`:

```sh
curl -F "file=@x.txt" -H "filename: <file_name>" "<server_address>"
curl -F "remote=https://example.com/file.png" -H "filename: <file_name>" "<server_address>"
```

### Server

To start the server:

```sh
$ rustypaste
```

If the configuration file is not found in the current directory, specify it via `CONFIG` environment variable:

```sh
$ CONFIG="$HOME/.rustypaste.toml" rustypaste
```

#### Authentication

##### OIDC

Configure `[auth]` to protect paste uploads, downloads, the landing page, the
list, version, and delete endpoints with a generic OpenID Connect provider. The
provider must allow this redirect URI, based on `[server].url`:

```text
https://paste.example.com/auth/callback
```

Browser requests without a session are redirected to the login flow. API
requests must authenticate with a CLI credential, service-account bearer token,
or compatible legacy token.

A minimal configuration is:

```toml
[server]
url = "https://paste.example.com"

[auth]
database_path = "./state/auth.sqlite3"
session_idle_timeout = "90d"
token_idle_timeout = "90d"
secure_cookies = true

[auth.oidc]
issuer_url = "https://identity.example.com"
client_id = "rustypaste"
client_secret = "replace-me"
scopes = ["openid", "profile", "email", "groups"]

[auth.authorization.required_claims]
groups = ["paste-users", "paste-admins"]

[auth.authorization.admin_claims]
groups = "paste-admins"
```

Secrets may also be supplied through config environment overrides, such as
`AUTH__OIDC__CLIENT_SECRET`, instead of being written to the TOML file.

Claim rules inspect top-level string claims or arrays of strings. All configured
claim keys must match, while an array in the configuration accepts any listed
value. Empty `required_claims` allows every identity accepted by the provider;
empty `admin_claims` grants no administrator access.

Browser sessions and CLI credentials use rolling 90-day idle timeouts by
default. Configure them independently with `session_idle_timeout` and
`token_idle_timeout`. Keep `secure_cookies = true` in production. Plain HTTP is
rejected unless `allow_insecure_http = true`, which is intended only for local
development. Each principal can have up to 32 active browser sessions and 32
dynamically issued CLI credentials; newer logins replace the oldest entries.

The SQLite database contains authentication and ownership metadata, not paste
contents. Keep `database_path` outside `[server].upload_path`, persist it across
restarts, and back it up with the upload directory.

Authentication settings are initialized at startup. Restart rustypaste after
changing `[auth]`, OIDC claim rules, service accounts, or legacy token settings.

Named service accounts provide bearer authentication for automation:

```toml
[auth.service_accounts.ci]
token_env = "RUSTYPASTE_CI_TOKEN"
admin = false
```

Each account must configure exactly one of `token`, `token_file`, or `token_env`.
Set `admin = true` only for automation that needs global listing and deletion.

The standalone [`rpaste`](https://github.com/orhun/rustypaste-cli) client uses a
browser-assisted device login:

```sh
$ rpaste -s "https://paste.example.com" auth login
$ rpaste -s "https://paste.example.com" auth status
$ rpaste -s "https://paste.example.com" auth logout
```

The login command displays a verification code, opens the verification page,
and stores a credential for that server. `status` verifies the current identity;
`logout` revokes and removes that credential.

##### Legacy tokens

To enable basic HTTP auth, set the `AUTH_TOKEN` environment variable (via `.env`):

```sh
$ echo "AUTH_TOKEN=$(openssl rand -base64 16)" > .env
$ rustypaste
```

There are 2 options for setting multiple auth tokens:

- Via the array field `[server].auth_tokens` in your `config.toml`.
- Or by writing a newline separated list to a file and passing its path to rustypaste via `AUTH_TOKENS_FILE` and `DELETE_TOKENS_FILE` respectively.

These static token settings remain compatible but are deprecated when `[auth]`
is enabled. Existing authentication tokens become a shared legacy principal;
existing delete tokens retain global deletion access without gaining other
administrator privileges. Prefer named
service accounts for new automation.

> When `[auth]` is not configured, the server will not require authentication if
> neither `AUTH_TOKEN`, `AUTH_TOKENS_FILE` nor `[server].auth_tokens` are set.
>
> Exception is the `DELETE` endpoint, which requires at least one token to be set. See [deleting files from server](#delete-file-from-server) for more information.

See [config.toml](./config.toml) for configuration options.

#### MIME handling

rustypaste determines a file's MIME type from its extension (with optional overrides) and serves
text-like types as `text/plain; charset=utf-8` to avoid script execution.

- `[paste].mime_override` lets you override MIME types by filename regex.
- `[paste].mime_blacklist` blocks uploads of specific MIME types.
- `[paste].text_mime_overrides` forces additional detected/guessed MIME types to be rendered as plaintext (unlike `mime_override` which matches by filename regex, this matches the content's actual MIME type).

#### List endpoint

Set `expose_list` to true in [config.toml](./config.toml) to retrieve a JSON
formatted list of pastes.

```sh
$ curl "http://<server_address>/list"

[{"file_name":"accepted-cicada.txt","file_size":241,"item_type":"file","creation_date_utc":"2026-07-14 22:15:00","expires_at_utc":null}]
```

This route will require an `AUTH_TOKEN` if one is set.

With OIDC enabled, `/list` returns only pastes owned by the authenticated
principal. Administrators can request the global view with:

```sh
$ curl -H "Authorization: Bearer <api_token>" \
  "https://paste.example.com/list?scope=all"
```

An exact paste link is shareable with any authenticated user; listing does not
grant or restrict link access. Paste owners can delete their own pastes, while
administrators can delete any paste. Files that already existed before OIDC was
enabled are reconciled as unowned: they remain available by exact link and only
administrators can discover them through the global list or delete them.

#### HTML Form

It is possible to use an HTML form for uploading files. To do so, you need to update two fields in your `config.toml`:

- Set the `[landing_page].content_type` to `text/html; charset=utf-8`.
- Update the `[landing_page].text` field with your HTML form or point `[landing_page].file` to your html file.

For an example, see [examples/html_form.toml](./examples/html_form.toml)

#### Docker

Following command can be used to run a container which is built from the [Dockerfile](./Dockerfile) in this repository:

```sh
$ docker run --rm -d \
  -v "$(pwd)/upload/":/app/upload \
  -v "$(pwd)/state/":/app/state \
  -v "$(pwd)/config.toml":/app/config.toml \
  --env-file "$(pwd)/.env" \
  -e "RUST_LOG=debug" \
  -p 8000:8000 \
  --name rustypaste \
  orhunp/rustypaste
```

- uploaded files go into `./upload` (on the host machine)
- OIDC state goes into `./state` when `[auth].database_path` is
  `/app/state/auth.sqlite3` (or `./state/auth.sqlite3` from the container workdir)
- set `AUTH_TOKEN` via `-e` or `--env-file` to enable legacy authentication, or
  configure `[auth]` for OIDC

You can build this image using `docker build -t rustypaste .` command.

If you want to run the image using [docker compose](https://docs.docker.com/compose/), simply run `docker-compose up -d`. (see [docker-compose.yml](./docker-compose.yml))

#### Nginx

Example server configuration with reverse proxy:

```nginx
server {
    listen 80;
    location / {
        proxy_pass                         http://localhost:8000/;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header X-XSS-Protection        "1; mode=block";
        add_header X-Frame-Options         "sameorigin";
        add_header X-Content-Type-Options  "nosniff";
    }
}
```

If you get a `413 Request Entity Too Large` error during upload, set the max body size in `nginx.conf`:

```nginx
http {
    # ...
    client_max_body_size 100M;
}
```

### Third Party Clients

- [dbohdan/ferripaste](https://github.com/dbohdan/ferripaste) - Alternative rustypaste CLI client
- [rukh-debug/rustypaste-gui.sh](https://gist.github.com/rukh-debug/cc42900f86e39cacef6f7a6ba77ebf58) - Linux's Minimal GUI client powered by zenity
- [ShareX](https://github.com/ShareX/ShareX) - ShareX as handy GUI client for rustypaste ([.sxcu profile example](https://gist.github.com/Null-Kelvin/c726a080762781a603cbc1b713d36cc6))
- [Silvenga/rustypaste-ui](https://github.com/Silvenga/rustypaste-ui) - A modern, single file, web UI to interact with the rustypaste server.

### Contributing

Pull requests are welcome!

Consider submitting your ideas via [issues](https://github.com/orhun/rustypaste/issues/new) first and check out the [existing issues](https://github.com/orhun/rustypaste/issues).

#### License

<sup>
All code is licensed under <a href="LICENSE">The MIT License</a>.
</sup>
