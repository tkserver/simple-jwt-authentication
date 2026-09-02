# Test Suite Task List — Simple JWT Authentication

> Goal: go from **zero tests** (see `TASKS.md` → "Deferred") to a meaningful
> regression suite that pins down the bugs this project has historically
> shipped: OOM recursion in `determine_current_user`, `user_id` int-vs-string
> crash, `Config::parseBool()` coercion, CORS `false` handling.
>
> Est. total: **~2–3 focused days**. Each task below is a separate, small,
> independently-doable unit of work. Do them in order — later tasks depend on
> earlier ones (dependencies marked **Deps:**).

Conventions:

- Test files live in `tests/` (mirrors `src/`)
- Namespace: `SimpleJwtAuth\Tests\`
- Pure-PHP tests = no WordPress required, run with plain PHPUnit
- WP-dependent tests = run against the shim layer from Phase 2
- Every task must leave the tree green (`php vendor…/phpunit` exits 0)

---

## Phase 0 — Scaffolding (no product code touched)

### Task 0.1 — Add dev dependencies to composer.json ✅ DONE (2026-09-01)
- [x] **Implementation deviation:** dev deps live in an isolated harness
      **`tests/composer.json`** (own `tests/vendor/`), NOT in the root
      `composer.json`. Rationale: the root config uses
      `"vendor-dir": includes/vendor`, which is *committed and shipped* —
      a full install would add ~100 PHPUnit files plus churn the committed
      `installed.json`/autoload files into the runtime bundle, and any future
      `composer install` on a deployed site would pull dev deps into the
      plugin. The isolated harness makes the "never ships PHPUnit" guarantee
      deterministic. Acceptance criterion preserved.
- [x] `phpunit/phpunit: ^10.5 || ^11` (resolved: PHPUnit **11.5.56**), scripts
      `composer test` / `composer test:unit` inside `tests/`
- [x] Verified: `git diff includes/vendor` empty (byte-identical);
      `tests/vendor/` ignored by the existing `.gitignore` `vendor/` rule;
      PHPUnit binary runs; runtime autoloader still resolves
      `\Firebase\JWT\JWT` and `\SimpleJwtAuth\Config`
- **Deps:** none
- **Effort:** ~30 min

### Task 0.2 — Create tests/ skeleton ✅ DONE (2026-09-01)
- [x] `tests/Unit/` (pure-PHP), `tests/WP/` (WP-shim dependent, `.gitkeep` until Phase 2)
- [x] `tests/bootstrap.php` — loads test-harness autoloader **then**
      `includes/vendor/autoload.php` (runtime); no WP loading by design
- [x] Smoke test runs green: `SkeletonSmokeTest` (3 tests — runtime classes,
      firebase/php-jwt, harness PSR-4 mapping)
- **Deps:** none
- **Effort:** ~20 min

### Task 0.3 — phpunit.xml.dist + .gitignore ✅ DONE (2026-09-01)
- [x] `phpunit.xml.dist` (repo root): suites `unit` (tests/Unit) + `wp` (tests/WP,
      empty until Phase 2); bootstrap, cache in `tests/artifacts/`,
      `failOnDeprecation/Warning/Risky`; `<source>` includes `src/`
- [x] `.gitignore`: added `tests/artifacts/` (result cache etc.)
- [x] Root `TASKS.md`: PHPUnit deferred item marked **in progress**, points here
- [x] Verified: `composer test` + `composer test:unit` green, exit 0
- **Deps:** 0.1, 0.2
- **Effort:** ~20 min

---

## Phase 1 — Pure-PHP unit tests (highest value, lowest cost)

### Task 1.1 — Config tests ✅ DONE (2026-09-01)
- [x] `tests/Unit/Config/ConfigParseBoolTest.php` — 23-case coercion table
      (regression anchor: v2.0.1 `(bool)'false'`)
- [x] `tests/Unit/Config/ConfigOptionsTest.php` — option paths: secret key
      (string/empty/missing/non-string), reset URL template, reset key max age
      (incl. negative/non-numeric clamps), getSettings cache-until-flush, CORS
      from options
- [x] `tests/Unit/Config/ConfigConstantsTest.php` — wp-config constant paths:
      new beats legacy beats option; empty-constant fall-through; legacy
      `JWT_AUTH_*` fallbacks; isGlobalDefined (locked-by-constant detection)
- [x] Shared stub layer created early to support this: `tests/helpers/wp-lite-stubs.php`
      (guarded global fns + WP_Error/WP_User + `SjwtTestState::reset()`) —
      Phase 2's shim will require_once it and layer on top
- [x] Config note: suite now runs with **processIsolation=true** (real PHP
      `define()` calls are per-test-process; constants cannot be undefined)
- [x] Verified: `composer test:unit` green — 65 tests / 68 assertions
- **Deps:** 0.2
- **Effort:** ~1 hr

### Task 1.2 — PasswordResetCode tests ✅ DONE (2026-09-01)
- [x] `tests/Unit/PasswordResetCode/PasswordResetCodeTest.php` — 12 tests:
      issue (6-digit default, length filter clamped 4–8, TTL filter clamped
      ≥60, payload hash/expires/attempts), verify (correct, missing record,
      wrong → attempt counter, burn-out at max_attempts → 429 + meta cleared,
      expired → cleared, non-numeric/empty rejected, whitespace stripped,
      re-issue invalidates old code), clear
- [x] Verified: `composer test:unit` green — 77 tests / 113 assertions
- **Deps:** 0.2
- **Effort:** ~1.5 hr

### Task 1.3 — TokenService JWT round-trip ✅ DONE (2026-09-01)
- [x] `tests/Unit/TokenService/TokenServiceRoundTripTest.php` — 16 tests:
      v1-shape login JSON (**user_id string**, regression anchor), jwt_data row
      stored (uuid4/ip/ua), sign→verify happy path, no/malformed header,
      missing secret (503), expired, not-yet-valid, tampered signature
      (re-signed payload), issuer mismatch both directions, garbage token
      string, payload without user id, revoked/unknown uuid, iss filter pins
      sign+verify. Notes: `home_url` → stubbed `get_bloginfo('url')`;
      firebase v7 requires ≥32-byte HS256 keys in the forging test
- [x] Verified: `composer test:unit` green — 107 tests / 197 assertions
- **Deps:** 0.2
- **Effort:** ~2 hr

### Task 1.4 — TokenService revocation & session bookkeeping ✅ DONE (2026-09-01)
- [x] `tests/Unit/TokenService/TokenServiceRevocationTest.php` — 13 tests:
      revoke current token (+ meta left as empty array, matching WP get_user_meta
      semantics), auth-error mapping in revoke response, expired pruning
      (order preserved), nothing-to-prune, session soft-cap keeps newest (filter
      `jwt_auth_max_tokens_per_user`), cap 0 = unlimited, expired pruned before
      append, `last_used` updated only via middleware path beyond the hourly
      window (write-amplification regression), default validateToken never
      touches meta, revokeAll counts + deletes
- [x] Verified: `composer test:unit` green — 107 tests / 197 assertions
- **Deps:** 1.3
- **Effort:** ~2 hr

### Task 1.5 — Bypass-route matcher tests ✅ DONE (2026-09-01)
- [x] `tests/Unit/Rest/RestControllerMiddlewareTest.php` — 16 tests:
      15-case bypass matrix (exact suffix matching only: `/token/validate/custom`
      does NOT bypass; trailing slashes; encoded + extra-query `?rest_route=`
      forms; pretty + non-pretty), public middleware behavior (non-REST URIs,
      bypass skips middleware even with Bearer, no-header leaves user, valid
      Bearer authenticates on BOTH permalink forms (2.1.1 regression), invalid
      Bearer → stored jwt error, Bearer beats earlier user, re-entry guard
      short-circuit (OOM regression), preDispatch translation + pass-through
- [x] Lite stubs extended with REST surface: `add_action`,
      `rest_get_url_prefix()` (configurable via `$GLOBALS['__sjwt_rest_prefix']`),
      `untrailingslashit()`
- [x] Verified: `composer test:unit` green — 132 tests / 231 assertions
- **Deps:** 0.2 (no refactor needed — private matcher exercised via reflection
      + public `determineCurrentUser`)
- **Effort:** ~1 hr

---

## Phase 2 — WP shim layer (decision + build)

### Task 2.1 — Harness decision memo ✅ DECIDED (2026-09-01): **(b) hand-rolled shim**

**Decision:** extend the existing lite stubs (`tests/helpers/wp-lite-stubs.php`)
into a full shim (`tests/WP/shim-functions.php`) instead of a real WP test env.

Rationale:
1. Phase 1 already ran with a guarded stub layer and process isolation — the
   architecture is proven; a real `wp-phpunit`/`wp-env` stack (MySQL, WP core
   install, plugin activation) would add ~½ day of ops setup with no additional
   fidelity for the behaviors under test (JWT logic, filters, meta/options).
2. The historical regressions this suite must pin are logic bugs (OOM
   recursion, int/`user_id`, coercion, matching) — all testable against a
   faithful function/class surface, not against WP core itself.
3. Deterministic environment: no DB, no network; CI runs `composer install`
   + `phpunit` only.
4. Trade-off accepted: the shim tests OUR interpretation of WP semantics, not
   WP itself. Guarded, single-source-of-truth design (`wp-lite-stubs.php` is
   `require_once`d by the shim; everything `function_exists`/`class_exists`
   checked) keeps drift visible; the lite stubs stay as lean as possible.
5. Revisit trigger: if an endpoint behavior turns out to hinge on WP internals
   beyond the shim's fidelity (e.g. real `WP_REST_Server` dispatch), flip to
   wp-env for that specific test — no rework of the pure suite needed.

- [x] Decision recorded before Phase 3 work
- **Deps:** none
- **Effort:** ~30 min

### Task 2.2 — Build WP function shim library ✅ DONE (2026-09-01)
- [x] `tests/WP/shim-functions.php` (require_once's the lite stubs, which
      already provide meta/options/filters/transients/`__`/`is_wp_error`):
      user store + `get_user_by`/`get_userdata`, `wp_hash_password`
      (deterministic), `wp_check_password`, `wp_set_password`,
      `wp_authenticate` (codes `invalid_username`/`incorrect_password`),
      `get_password_reset_key` + `check_password_reset_key` (honors the
      `password_reset_expiration` filter → the plugin's own constructor
      filter is exercised), `wp_mail` (records to `$GLOBALS['__sjwt_sent_mail']`,
      honors the `wp_mail` filter's `do_not_send`), `network_home_url`/
      `network_site_url`, `is_multisite`, `wp_specialchars_decode`,
      `do_action` (runs registered actions), HTTP surface `status_header`/
      `header`/`wp_die`, minimal `WP_REST_Request`/`WP_REST_Response`
- [x] **Deviation (rationale):** functions listed in the plan that turned out
      unused by `src/` were NOT stubbed: `wp_json_success`,
      `wp_generate_password`, `get_site_option`, `current_time`, `home_url`,
      `wp_send_*`
- [x] Options/meta backed by in-memory arrays (reset per test) — via the
      generic `SjwtTestState::reset()` loop clearing every `__sjwt_*` key
- [x] Filter registry honoring `apply_filters` (+ `accepted_args`)
- [x] `SjwtWpdb` test double: `prepare` (%d/%s/%f), `query` reproduces the
      plugin's atomic activation-key compare-and-clear (first caller wins,
      concurrent caller gets 0), `update`
- [x] Verified: CLI include smoke (auth, reset-key lifecycle, wpdb flow,
      `wp_mail`) + unit suite still green (132 tests)
- **Deps:** 2.1
- **Effort:** ~4 hr (bulk of Phase 2)

### Task 2.3 — Minimal WP classes shim ✅ DONE (2026-09-01)
- [x] `WP_Error`, `WP_User` live in the lite stubs; `WP_User` extended with
      `user_pass`/`user_activation_key` (needed by the reset flows) + data obj
- [x] `WP_REST_Response`: data/status/headers with `header()`,
      `get_status()`, `get_data()`, `get_headers()`
- [x] `WP_REST_Request`: `get_param`/`get_params`/`has_param`/`set_param`
- [x] All `class_exists`-guarded so a real WP wins if loaded first
- **Deps:** 2.2
- **Effort:** ~1 hr

---

## Phase 3 — Endpoint & middleware tests (WP shim suite)

### Task 3.1 — POST /token ✅ DONE (2026-09-01)
- [x] `tests/WP/TokenEndpointLoginTest.php` — 8 tests: happy path 200 + v1
      shape (token, **`user_id` string '42'** [regression], `user_email`,
      `user_nicename`, `user_display_name`, `token_expires` int), payload
      decode (identity at `data.user.id`, `uuid` present, `iss` from blog URL),
      wrong password → 401 `[jwt_auth] incorrect_password`, unknown user → 401
      `[jwt_auth] invalid_username` (WP error code passed through), missing
      secret → 503 `jwt_auth_bad_config`, rate limit exceeded → 429 +
      `Retry-After` (= window), success resets the failure counter, blocked
      bucket is never reset by refused attempts
- [x] Learned while writing: transient store rows are `['e' => expiry,
      'v' => value]` (e=0 = never expires); login payload has **no `sub`
      claim** — identity lives at `data.user.id`
- [x] Verified: `composer test` green — 140 tests / 255 assertions
- **Deps:** 2.2, 2.3
- **Effort:** ~2 hr

### Task 3.2 — POST /token/validate + /token/revoke ✅ DONE (2026-09-01)
- [x] `tests/WP/TokenEndpointValidateRevokeTest.php` — 11 tests: valid Bearer
      → 200 `jwt_auth_valid_token`; missing header → 401 `jwt_auth_no_auth_header`;
      expired (forged exp) → 401 `jwt_auth_expired_token` (exp check runs
      during decode, *before* the revocation lookup); garbage → 401
      `jwt_auth_invalid_token`; revoked → 403 + translated "Token has been
      revoked."; revoke clears `jwt_data` meta and a subsequent validate → 403
      `jwt_auth_token_revoked` (pinned: NOT 404/invalid_token); revoke without
      token → **outer 403 with inner data.status 401** (endpoint maps
      everything except revoked/no-token-to-revoke to outer 403 — documented
      mapping quirk); revoke twice → second attempt 403/403; validate without
      secret → 503 (header is checked first — Bearer must be supplied);
      endpoint validate never stores the jwt error (middleware-only handoff)
- [x] Learned: HMAC forging requires the raw secret string (not a `Key`
      object); validate check order: header → secret → decode/iss → uuid
- [x] Verified: `composer test` green — 151 tests / 284 assertions
- **Deps:** 3.1
- **Effort:** ~1.5 hr

### Task 3.3 — POST /token/resetpassword (request) ✅ DONE (2026-09-01)
- [x] `tests/WP/TokenEndpointResetRequestTest.php` — 13 tests: generic 200 for
      known/unknown/empty username (no mail for unknown/empty → **no username
      enumeration**, regression 2.0.1), email-as-username resolves, message
      contents (site URL, `Username: jane`, client IP, OTP), **OTP extracted
      from the email verifies against meta** (end-to-end), core reset key
      stored + `wp-login.php?action=rp&key=…&login=…` deep link in message,
      `reset_url_template` replaces the deep link entirely with `{key}`/
      `{login}` filled (no `wp-login.php` left in message), **mail failure
      drops the OTP** (meta cleared — no stuck codes), throttle skips the send
      but still 200 and does not bump the bucket, `allow_password_reset`
      filter blocks send, `lostpassword_post` fires only for known users,
      `retrieve_password_title` filter renames subject
- [x] Learned: test must not re-create the user row after
      `get_password_reset_key` (it would wipe `user_activation_key`)
- [x] Verified: `composer test` green — 164 tests / 324 assertions
- **Deps:** 2.2, 2.3
- **Effort:** ~2 hr

### Task 3.4 — POST /token/resetpassword/complete ✅ DONE (2026-09-01)
- [x] `tests/WP/TokenEndpointResetCompleteTest.php` — 13 tests: missing login/
      code → 400 `jwt_auth_invalid_code`; short password → 400
      `jwt_auth_password_too_short` (+ `jwt_auth_reset_password_min_length`
      filter respected); **OTP happy path changes the password** (verified via
      `wp_check_password` against the fresh hash) and cleans up everything:
      OTP meta cleared, deep-link key burned (`user_activation_key`), **all
      sessions revoked** (`jwt_data` emptied), `password_reset` action fired
      (args 1..2 via accepted_args), confirmation email opt-in subject,
      reset-complete bucket bumped even on success; wrong code → 400 + attempts
      counter bumped; burn-out (max_attempts filter=1) → 429 + `Retry-After`
      900 + code cleared; blocked bucket → 429 without consuming; expired key
      → 400 `jwt_auth_invalid_key`; legacy `key=` happy path → 200 + password
      changed; **reused key fails the compare-and-clear** (second attempt 400,
      password untouched); base64 `account` param accepted; `retrieve_password_user`
      filter can block → 403 `jwt_auth_reset_password_not_allowed`;
      `jwt_auth_send_reset_confirmation_email` opt-out honored (no mail)
- [x] Shim hardened: `check_password_reset_key` now also requires the user's
      activation key to match (burned keys fail)
- [x] Verified: `composer test` green — 177 tests / 376 assertions
- **Deps:** 3.3
- **Effort:** ~2 hr

### Task 3.5 — Auth middleware ✅ DONE (2026-09-01) — merged into Task 1.5
- [x] All three planned scenarios (Bearer authenticates REST request, re-entry
      guard / OOM regression, non-pretty permalink `?rest_route=`) are pinned
      by `tests/Unit/Rest/RestControllerMiddlewareTest.php` (Task 1.5). The
      middleware surface is WP-agnostic — `RestController` reads `$_SERVER`
      + `TokenService` directly; the WP shim adds no new behavior here, so a
      duplicate shim-suite test would re-run identical assertions.
- [x] Revisit trigger recorded: if `determine_current_user` semantics ever
      start depending on real WP core behavior beyond the shim, add a shim-level
      test then.
- **Deps:** 2.2, 2.3 (covered by 1.5 instead)
- **Effort:** ~2 hr → ~0

### Task 3.5 — Auth middleware
- [x] Bearer token authenticates `determine_current_user` on authenticated REST call
- [x] **Re-entry guard**: nested current-user lookup doesn't recurse (OOM regression)
- [x] Non-pretty permalink (`?rest_route=`) requests still honor Bearer (regression: 2.1.1)
      (all three pinned by Task 1.5 — see above)
- **Deps:** 2.2, 2.3
- **Effort:** ~2 hr

### Task 3.6 — CORS ✅ DONE (2026-09-01)
- [x] `tests/WP/RestControllerCorsTest.php` — 11 tests: disabled by default
      sends nothing; **`enable_cors: 'false'` actually disables** (parseBool
      regression); default headers on namespace routes (ACAO `*` +
      `Content-Type, Authorization`); other-plugin routes ignored;
      `jwt_auth_cors_allow_origin`/`_headers` filters reflected; OPTIONS
      preflight → `status_header(204)` + 4 headers (methods, max-age 86400) +
      `wp_die()` recorded; preflight ignores non-OPTIONS + other routes;
      header list contains Authorization/Content-Type and **no bogus
      self-referential entry**; legacy `JWT_AUTH_CORS_ENABLE` const enables
- [x] Learned: `header()` is a PHP built-in — a global stub can never load.
      Fixed with a namespace-scoped shadow in the plugin's own namespace
      (`tests/WP/shim-ns-header.php`), which unqualified calls inside
      `namespace SimpleJwtAuth\Rest` resolve first; `register_rest_route()`
      stub records route registrations (`__sjwt_rest_routes`)
- [x] Verified: `composer test` green — 188 tests / 399 assertions
- **Deps:** 2.2, 2.3
- **Effort:** ~1 hr

---

## Phase 4 — Packaging & CI

### Task 4.1 — Keep dev deps out of the shipped plugin ✅ DONE (2026-09-01)
- [x] Verified: `git diff includes/vendor` empty (dev deps install only in
      `tests/vendor`, per the 0.1 deviation); `.gitignore` already covers
      `tests/vendor/` (existing `vendor/` rule), `tests/artifacts/` and
      `*.phpunit.result.cache`
- [x] CI guard step added: workflow asserts `includes/vendor` stays clean
      after test-dep install
- [x] Note: commit `tests/composer.lock` (currently untracked) for
      reproducible installs
- **Deps:** 0.1
- **Effort:** ~30 min

### Task 4.2 — Test runner script + CI ✅ DONE (2026-09-01)
- [x] `tests/run.sh` (executable, `bash -n` clean): auto-installs test deps,
      runs both suites via `vendor/bin/phpunit --testdox -c
      ../phpunit.xml.dist`, passes args through (`-- --filter=...`)
- [x] `.github/workflows/phpunit.yml`: PHP 8.2/8.3 matrix, `composer validate`
      for root + tests configs, test-dep install, both suites, vendor-leak guard
- [x] Verified locally: full suite green (see 4.3)
- **Deps:** all suites runnable
- **Effort:** ~1 hr

### Task 4.3 — Docs ✅ DONE (2026-09-01)
- [x] README.md: "Development / Testing" section added (how to run, suite
      layout, process isolation, WP shim is test-only, CI pointer)
- [x] Root TASKS.md: deferred PHPUnit item marked done, links here
- [x] Changelog drift synced conservatively: added a `2.2.1` entry (version
      bump; noted the 2.2.x line's entries were not recorded) + test suite
      addition — no invented feature list
- [x] Final verification: `composer test` green — 188 tests / 399 assertions
- **Deps:** 4.2
- **Effort:** ~30 min

---

## Summary

| Phase | Tasks | Est. |
|---|---|---|
| 0 Scaffolding | 3 | ~1.2 hr |
| 1 Pure-PHP unit | 5 | ~7.5 hr |
| 2 WP shim | 3 | ~5.5 hr |
| 3 Endpoints | 6 | ~10.5 hr |
| 4 Packaging/CI/docs | 3 | ~2 hr |

One task per session. Tasks 1.1–1.5 and 2.2–2.3 are the load-bearing ones;
everything after them is incremental.
