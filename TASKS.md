# Task List — v2.0.1 hardening pass

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

- [ ] Automated test suite (PHPUnit) — out of scope for this pass; `.gitignore` already
  anticipates it.
- [ ] Optional: IP-based client IP behind proxy (`X-Forwarded-For`) — intentionally not
  trusted by default.
