# Simple JWT Authentication

Extends the WP REST API using JSON Web Tokens (JWT) as an authentication method, with support for token revocation and password reset.

> **Fork** of [Simple JWT Authentication](https://github.com/jonathan-dejong/simple-jwt-authentication), originally created by Jonathan de Jong.

[Documentation](https://github.com/jonathan-dejong/simple-jwt-authentication/wiki/Documentation)

## Requirements

- PHP >= 8.2
- WordPress >= 6.4

## Installation

1. Upload the plugin to `/wp-content/plugins/simple-jwt-authentication/`
2. Activate via **Plugins → Simple JWT Authentication**
3. Configure under **Settings → Simple JWT Authentication** (or define constants in `wp-config.php`)

## Configuration

Either set the secret key in the admin settings page, or in `wp-config.php`:

```php
define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', 'your-long-random-string');
define('SIMPLE_JWT_AUTHENTICATION_CORS_ENABLE', true); // optional
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/wp-json/simple-jwt-authentication/v1/token` | Authenticate & receive a JWT |
| POST | `/wp-json/simple-jwt-authentication/v1/token/validate` | Validate a Bearer token |
| POST | `/wp-json/simple-jwt-authentication/v1/token/revoke` | Revoke the current token |
| POST | `/wp-json/simple-jwt-authentication/v1/token/resetpassword` | Request a password reset email |

## Usage

```bash
# Get a token
curl -X POST https://example.com/wp-json/simple-jwt-authentication/v1/token \
  -d "username=admin&password=secret"

# Use the token
curl -H "Authorization: Bearer <token>" \
  https://example.com/wp-json/wp/v2/posts
```

## Architecture (v2.0)

```
src/
├── Plugin.php           # Orchestrator
├── Config.php           # Settings accessor (constants or DB)
├── TokenService.php     # JWT encode/decode/validate/revoke
├── Rest/
│   ├── RestController.php   # Route registration + auth middleware
│   └── TokenEndpoint.php    # Endpoint handlers
└── Admin/
    ├── SettingsPage.php     # Admin settings UI
    ├── ProfileTokens.php    # User profile token management
    └── Views/               # Templates
```

Namespace: `SimpleJwtAuth\` (PSR-4, autoloaded via Composer).

## Changelog

### 2.0.1
- Security: `/token/resetpassword` now returns a single generic response for all
  outcomes (no username enumeration), and only fires core lost-password actions
  for existing users
- Security: per-IP rate limiting on `/token` (failed logins, 429 + `Retry-After`)
  and on `/token/resetpassword` (email sends); filterable via
  `jwt_auth_login_rate_limit_max` / `_window` and `jwt_auth_reset_rate_limit_max` /
  `_window`
- Security: functional CORS — `Access-Control-Allow-Origin` (filter
  `jwt_auth_cors_allow_origin`) plus `OPTIONS` preflight handling (204,
  `Access-Control-Allow-Methods`, `Access-Control-Max-Age`); corrected default
  `Access-Control-Allow-Headers`
- Performance: `jwt_data` user meta is no longer rewritten on every authenticated
  request — `last_used` updates hourly (filter `jwt_auth_last_used_update_interval`)
  and only when something changed
- Data: expired token entries are auto-pruned during verification
- Fix: `Config::parseBool()` for string CORS constants (`'false'` was cast to `true`)
- Fix: auth-middleware bypass routes now match exact paths only
- `uninstall.php` removes token metadata in a single query
- Actually uses `readonly` properties (as documented)
- New filter: `jwt_auth_token_iss` to pin the token issuer

### 2.0.0
- **Breaking:** Requires PHP 8.2+ and WordPress 6.4+
- **Breaking:** `firebase/php-jwt` upgraded v3 → v7 (tokens signed with v7 use the same HS256 algorithm, so existing tokens remain valid)
- Restructured to PSR-4 under `src/` with `SimpleJwtAuth\` namespace
- Extracted `TokenService`, `Config`, `RestController`, `TokenEndpoint` classes
- Removed unused `donatj/phpuseragentparser` dependency
- Security: `hash_equals()` for token comparison, nonces on admin actions, `esc_*` in views
- REST: proper HTTP status codes (401/403/404/503), `WP_REST_Response` throughout
- PHP 8.2 features: `strict_types`, typed properties, constructor promotion, `fn()`, `match`, `readonly`
- `uninstall.php` now removes options and user meta

### 1.1
- Bug fixes

### 1.0
- Initial release
