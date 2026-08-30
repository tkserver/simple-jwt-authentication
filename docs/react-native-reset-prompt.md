# Prompt for the React Native project

Paste this into the assistant working on the mobile app. It is self-contained —
it assumes nothing about the WordPress backend beyond the API contract below.

---

Implement a complete in-app password reset feature for this React Native app.
The backend is a WordPress site with a JWT auth plugin. The user must be able
to reset their password entirely inside the app, triggered either from the
login screen ("Forgot password?") or after a 401. Do not use any web view —
the flow is fully native, but the reset *key* arrives via email as a deep link
into the app.

## API contract

Base URL: `<API_BASE>` (already configured in the app for normal API calls).
All endpoints are `POST` with a form-encoded body
(`Content-Type: application/x-www-form-urlencoded`). All error responses share
this shape:

```json
{ "code": "<machine_code>", "message": "<human readable, display this>", "data": { "status": <int> } }
```

### 1. Request reset — `POST <API_BASE>/wp-json/simple-jwt-authentication/v1/token/resetpassword`

- Body: `username=<login or email>`
- **Always returns HTTP 200**, whether or not the account exists:
  `{ "code": "jwt_auth_password_reset", "message": "If the username or email address exists on this site, a password reset link has been sent.", "data": { "status": 200 } }`
- Never branch UI on response content for this call. The user should always see the same outcome screen.

### 2. Complete reset — `POST <API_BASE>/wp-json/simple-jwt-authentication/v1/token/resetpassword/complete`

- Body: `key=<key from deep link>`, `login=<login from deep link>`, `new_password=<new password>`
- Success 200: `{ "code": "jwt_auth_password_reset_complete", "message": "Your password has been reset. You can now sign in with your new password.", "data": { "status": 200 } }`
- Errors:
  - `jwt_auth_invalid_key` (HTTP 400) — key/login missing, unknown, expired, too old, or already used → tell the user the link expired and offer a "Request a new link" button that re-runs flow step 1 with the login name from the deep link
  - `jwt_auth_too_many_attempts` (HTTP 429) — too many completion attempts from this network; show the `message` field and respect `Retry-After`
  - `jwt_auth_password_too_short` (HTTP 400) — minimum is 8 characters (validate client-side before submitting)
  - `jwt_auth_reset_password_not_allowed` (HTTP 403) — show the `message` field
  - `jwt_auth_password_set_failed` (HTTP 500) — show the `message` field
- On success the backend revokes every previously issued JWT for that account.
- The `{login}` placeholder must be included in the deep link template (see the
  Reset URL Template setting) — completion now requires both `key` and `login`.

### 3. Login (existing endpoint, for the follow-up step)

`POST .../v1/token` with `username`/`password` — already implemented in the app.
After a successful reset you must discard the stored token (if any) and navigate
to the login screen.

## Deep link contract

The reset email contains the link:

```
myapp://reset-password?key=<KEY>&login=<USERNAME>
```

(`{key}` and `{login}` are URL-encoded by the backend.)

Implement:

1. **iOS**: register the `myapp` URL scheme in `Info.plist` (`CFBundleURLTypes`).
2. **Android**: intent filter in `AndroidManifest.xml` for `android:scheme="myapp"` `android:host="reset-password"` with `DEFAULT` and `BROWSABLE` categories.
3. **Cold start**: on app launch, check `Linking.getInitialURL()` — if it matches, route to the new-password screen before the user lands on their normal home flow.
4. **Warm start**: subscribe to `Linking.addEventListener('url')` at the app root; if the URL matches, navigate to the new-password screen with `{ key, login }` params (parse with `new URL(url).searchParams`).
5. If the user arrives on the new-password screen **without** a key (e.g. they navigated there some other way), render a form asking for their username/email and route into step 1 first.

## Screens

1. **ResetRequested** ("Check your email") — shown after step 1. Display the generic message, the email/username they entered, a "Resend" button (rate-limited server-side: max 5 sends per 15 minutes per IP, after which resends silently do nothing — so disable the resend button for ~15 minutes after the first request and label it accordingly), and a "Back to login" link.
2. **NewPassword** — two fields (new password, confirm) with a strength hint, 8-char minimum enforced client-side, password visibility toggle, submit button with loading + error states. Map API errors to the user-facing copy described above. On success show the success message from the API, then navigate to login after a short delay (or a "Continue to login" button).
3. **Login screen** — add a "Forgot password?" link that navigates to a small first screen asking for username/email and calls step 1.

## Security & behavior requirements

- Never persist the reset key. Keep it in memory for the duration of the NewPassword screen only; clear it when the user leaves the screen or the reset completes.
- On successful reset, delete the stored JWT from secure storage and force re-login — the old token is dead server-side.
- On any 401/403 from the general API client, the existing re-auth handling applies (unchanged).
- All network code should reuse the app's existing HTTP wrapper/base-URL config; only add the two reset endpoints and the deep link plumbing.
- Write the user-facing copy as constants in one place, and make the deep link scheme a single configurable constant (`myapp`, overridable via the app's env/config) so the team can rename it.
- Add unit tests for: deep link URL parsing (encoded key/login, missing params, wrong host, non-matching URLs), cold-start vs warm-start routing, the 8-char client validation, and error-code → user message mapping. Mock the HTTP layer; do not hit the real API in tests.

## Definition of done

- User can reset a forgotten password end-to-end in the app: tap "Forgot password?" → enter identity → "check your email" screen → tap emailed link (cold or warm start) → set new password → back at login with fresh token flow.
- Expired/invalid key path re-requests the link without leaving the app.
- No web view anywhere in the flow.
