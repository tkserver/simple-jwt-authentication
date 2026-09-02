# Task List — v2.1.1

## v2.1.1 — login OOM / determine_current_user recursion

- [x] PHP Fatal "Allowed memory size exhausted … in user.php on line 3845"
  during mobile-app login. Classic JWT infinite loop: `validateToken()` ran
  on `determine_current_user` and called `__()` / locale resolution, which
  re-entered `wp_get_current_user()` → OOM. Fix:
  - No `__()` inside `TokenService::validateToken()` / middleware path;
    translate at REST response boundary (`TokenEndpoint` / `preDispatch`).
  - Re-entry guard (`$determiningUser`) so nested current-user lookups bail.
  - Issuer via `home_url()` (filter still `jwt_auth_token_iss`).
  - Bypass-route matcher + REST detection handle pretty + `?rest_route=` forms
    (Bearer was ignored entirely on non-pretty installs).
- [x] Soft-cap concurrent `jwt_data` sessions per user (default 50, filter
  `jwt_auth_max_tokens_per_user`); prune expired before append on login.
- [x] Accept legacy wp-config constants `JWT_AUTH_SECRET_KEY` /
  `JWT_AUTH_CORS_ENABLE` (utehub.com still defines these; v2 only looked for
  `SIMPLE_JWT_AUTHENTICATION_*`, causing live 503 "key is missing").
- [x] Login JSON `user_id` must be a **string** (v1 returned `$user->data->ID`).
  v2 returned an int; React Native `AsyncStorage.setItem('user_id', number)`
  throws and crashes the mobile app on successful login.

## v2.1.0

- [x] `/token/resetpassword` emailed `wp-login.php` link can't be used by a
  pure mobile app. New **Reset URL Template** setting (admin option
  `reset_url_template` / `SIMPLE_JWT_AUTHENTICATION_RESET_URL_TEMPLATE`
  constant) with `{key}` / `{login}` placeholders, applied in
  `TokenEndpoint::applyResetUrlFilters()` before the existing
  `jwt_auth_reset_url` / `lostpassword_url` filters. Empty = core behavior.
- [x] WP core reset keys never expire (forwarded email = permanent reset
  vector). New **Reset Key Max Age** setting (`reset_key_max_age_hours` /
  `SIMPLE_JWT_AUTHENTICATION_RESET_KEY_MAX_AGE`, hours; 0 = no expiry).
  `jwt_reset_key_created` user meta tracks issuance; expired keys are
  rotated on re-request and rejected by `/token/resetpassword/complete`.
  Full revocation on reset also clears the meta; `uninstall.php` removes it.
- [x] Documents the previously unlisted `/token/resetpassword/complete`
  endpoint in README.md.

## v2.0.1 hardening pass

Security/robustness fixes found during project analysis.

## Security (high)

- [x] `/token/resetpassword` — returned distinct 400 "Invalid username" (username enumeration)
  and sent an email per request (DoS). Now a single generic 200 response for all outcomes
  (matches WP core `wp-login.php?action=lostpassword` behavior); `lostpassword_post` /
  `retrieve_password` actions only fire for existing users.
- [x] `/token` had no brute-force protection. Added per-IP failure counter via transients
  (429 + `Retry-After` when exceeded; reset on success). Filterable:
  `jwt_auth_login_rate_limit_max` (10), `jwt_auth_login_rate_limit_window` (15 min).
  `resetpassword` email sends also throttled per IP:
  `jwt_auth_reset_rate_limit_max` (5), `jwt_auth_reset_rate_limit_window` (15 min).
  Note: uses `REMOTE_ADDR`; behind a proxy all clients share one bucket (by design —
  no `X-Forwarded-For` trust).
- [x] CORS was non-functional (headers list only, no origin, no preflight). Now sends
  `Access-Control-Allow-Origin` (filterable, default `*`), answers `OPTIONS` preflight with
  204 + full CORS headers, and the default `Access-Control-Allow-Headers` no longer
  contains the bogus `Access-Control-Allow-Headers` entry: `jwt_auth_cors_allow_origin`,
  `jwt_auth_cors_allow_headers`.

## Performance / data hygiene (medium)

- [x] Every authenticated REST call wrote `jwt_data` user meta (unbounded write amplification).
  `last_used` now only updated every hour (filter `jwt_auth_last_used_update_interval`),
  and the meta row is only written back when something actually changed.
- [x] `jwt_data` grew unbounded. Expired entries are now pruned in the same pass as
  verification (the manual "Remove all expired tokens" admin button remains).
- [x] `Config::isCorsEnabled()` — `(bool) 'false'` was `true` when defined as a string
  constant. Added `Config::parseBool()` for correct coercion.
- [x] `determineCurrentUser` bypass routes used `str_contains` (e.g.
  `/.../token/validate/custom` skipped auth middleware). Now strict path-suffix matching.

## Maintenance (low)

- [x] `uninstall.php` looped over every user (N meta deletes). Single SQL
  `DELETE FROM usermeta WHERE meta_key = 'jwt_data'`.
- [x] README claimed `readonly` props existed; none did. Now actually used in
  `Plugin`, `RestController`, `TokenEndpoint`, `ProfileTokens`.
- [x] Token `iss` was hard-bound to `get_bloginfo('url')` (domain change = silent mass revocation).
  New filter `jwt_auth_token_iss` (used in sign + verify) lets a stable value be pinned.

## Deferred

- [x] Automated test suite (PHPUnit) — **done (2026-09-01)**: `tests/` with a
  pure-PHP unit suite (`tests/Unit/`) and a WP-shim endpoint suite
  (`tests/WP/`); 188 tests / 399 assertions, green. Run with
  `cd tests && composer test` (or `tests/run.sh`); CI:
  `.github/workflows/phpunit.yml` (PHP 8.2/8.3 matrix). Full breakdown and
  decisions: `TEST-SUITE-TASKS.md`.
- [ ] Optional: IP-based client IP behind proxy (`X-Forwarded-For`) — intentionally not
  trusted by default.
