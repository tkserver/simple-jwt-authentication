=== Simple JWT Authentication ===
Contributors: tkserver, jonathan-dejong
Tags: wp-rest, api, jwt, authentication, access
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.2
Stable tag: 2.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Extends the WP REST API using JSON Web Tokens Authentication as an authentication method, with token revocation and password reset.

== Description ==

Easily extends the WP REST API using JSON Web Tokens (JWT) as an authentication method. Includes the ability to revoke access for users at any time from the user profile page.

**Fork** of [Simple JWT Authentication](https://github.com/jonathan-dejong/simple-jwt-authentication), originally created by Jonathan de Jong.

**Requirements:** PHP 8.2+, WordPress 6.4+

== Installation ==

1. Upload the plugin to the `/wp-content/plugins/simple-jwt-authentication/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Go to **Settings → Simple JWT Authentication** to configure the secret key

Alternatively, define in `wp-config.php`:
`define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', 'your-key');`

== Changelog ==

= 2.0.1 =
* Security: password reset endpoint no longer reveals whether an account exists
* Security: per-IP rate limiting on login and password reset (429 when exceeded)
* Security: functional CORS (origin header + OPTIONS preflight)
* Performance: reduced user-meta writes on authenticated requests
* Data: expired tokens auto-pruned; faster uninstall
* Fix: string CORS constants and auth-middleware route matching
* New: jwt_auth_token_iss, jwt_auth_cors_allow_origin filters

= 2.0.0 =
* Breaking: Requires PHP 8.2+ and WordPress 6.4+
* Breaking: firebase/php-jwt upgraded v3 → v7
* PSR-4 autoloading with SimpleJwtAuth\ namespace
* Extracted TokenService, Config, RestController, TokenEndpoint
* Removed unused phpuseragentparser dependency
* Security: hash_equals, nonces, esc_* in views
* REST: proper status codes, WP_REST_Response
* PHP 8.2 features: strict_types, typed props, fn(), match, readonly
* uninstall.php cleans up options + user meta

= 1.1 =
* Bug fixes

= 1.0 =
* Initial version

== Upgrade Notice ==

= 2.0.1 =
* Security hardening: rate limiting, CORS preflight, password-reset response uniformity.

= 2.0.0 =
* Major refactor. Requires PHP 8.2+. Existing HS256 tokens remain valid.
