# Simple JWT Authentication — React Native Integration Guide

How to authenticate a React Native mobile app against this plugin, including the
full in-app password reset flow (v2.1.0+).

All endpoints live under the namespace:

```
/wp-json/simple-jwt-authentication/v1
```

Replace `wp-json` with your site's actual REST prefix if it differs, and `example.com`
with your domain below.

---

## 1. Server-side setup (WordPress admin)

**Settings → Simple JWT Authentication:**

| Setting | Value | Notes |
|---|---|---|
| Secret Key | long random string, e.g. `wp cli` or any CSPRNG output | Required. HS256 signing key. Alternatively `define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', '...')` in `wp-config.php` |
| Enable CORS | off | **Leave off** for a native app — the RN network stack does not enforce CORS. Only enable if you also ship a web build or in-app WebView |
| Reset URL Template | `myapp://reset-password?key={key}&login={login}` | Makes the emailed reset link open *your app* instead of `wp-login.php`. `{key}` and `{login}` placeholders are filled in. Leave empty to keep the web link |
| Reset Key Max Age (hours) | e.g. `24` | Reset keys are rotated after this window and rejected by the complete endpoint after it expires. `0` = no expiry (WordPress core behavior) |

Alternatively in `wp-config.php`:

```php
define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', 'your-long-random-string');
define('SIMPLE_JWT_AUTHENTICATION_RESET_URL_TEMPLATE', 'myapp://reset-password?key={key}&login={login}');
define('SIMPLE_JWT_AUTHENTICATION_RESET_KEY_MAX_AGE', 24); // hours
```

Filterable overrides (in a mu-plugin if you don't want to touch the settings UI):
`jwt_auth_expire` (token lifetime, default 183 days), `jwt_auth_reset_url`,
`jwt_auth_reset_password_min_length`, `jwt_auth_send_reset_confirmation_email`,
and all `jwt_auth_*_rate_limit_*` knobs. Reset key expiry is controlled by the
Reset Key Max Age setting (hours; 0 = core default, no expiry).

---

## 2. API endpoints

### 2.1 `POST /token` — log in, get a JWT

**Request** (form-encoded or JSON body):

```
username=<login>
password=<password>
```

**Success `200`:**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLC...",
  "user_id": 7,
  "user_email": "admin@example.com",
  "user_nicename": "admin",
  "user_display_name": "admin",
  "token_expires": 1845012345
}
```

`token_expires` is a Unix timestamp. Default lifetime is 183 days
(shorten with the `jwt_auth_expire` filter — see §4).

**Errors:**

| Status | `code` | When |
|---|---|---|
| `401` | `[jwt_auth] invalid_credentials` (or other WP auth code) | Bad username/password |
| `429` | `jwt_auth_too_many_attempts` | 10+ failed logins per IP in 15 min. Includes a `Retry-After` header (seconds). Counter resets on a successful login |
| `503` | `jwt_auth_bad_config` | No secret key configured |

Error body shape is always `{ "code", "message", "data": { "status" } }`.

---

### 2.2 `POST /token/validate` — check the current Bearer token

**Request:** no body. Send the token as `Authorization: Bearer <token>`.

**Success `200`:**

```json
{ "code": "jwt_auth_valid_token", "data": { "status": 200 } }
```

**Errors:** `401` (missing/malformed header, expired, bad signature, revoked),
`403` (issuer mismatch, user missing from payload, revoked), `503` (not configured).
Same body shape as above.

---

### 2.3 `POST /token/revoke` — revoke the current Bearer token

**Request:** no body, with `Authorization: Bearer <token>`.

**Success `200`:**

```json
{ "code": "jwt_auth_revoked_token", "data": { "status": 200 } }
```

**Errors:** `404` `jwt_auth_no_token_to_revoke` (not found in the stored list),
`403` (validation failed — e.g. already expired/revoked). The token is useless after
either outcome.

---

### 2.4 `POST /token/resetpassword` — request a password reset email

**Request:**

```
username=<login or email address>
```

**Response — always a generic `200`, regardless of whether the account exists:**

```json
{
  "code": "jwt_auth_password_reset",
  "message": "If the username or email address exists on this site, a password reset link has been sent.",
  "data": { "status": 200 }
}
```

This uniformity is intentional (no username enumeration). The email contains a link
built from the **Reset URL Template** setting — with the template configured, the
link is your app's deep link, e.g. `myapp://reset-password?key=AbCd123...&login=admin`.
Email sends are rate-limited per IP (5 per 15 min by default); over budget the email
is silently skipped but the response is still 200.

---

### 2.5 `POST /token/resetpassword/complete` — set the new password

**Request:**

```
key=<key from the deep link / email>
new_password=<new password>
```

**Success `200`:**

```json
{
  "code": "jwt_auth_password_reset_complete",
  "message": "Your password has been reset. You can now sign in with your new password.",
  "data": { "status": 200 }
}
```

After success: all of that user's existing JWTs are **revoked server-side** (their
devices' tokens stop validating), the reset key is cleared, and a confirmation email
is sent (opt-out via `jwt_auth_send_reset_confirmation_email`).

**Errors:**

| Status | `code` | When |
|---|---|---|
| `400` | `jwt_auth_invalid_key` | Key missing, unknown, expired, or older than the configured max age |
| `400` | `jwt_auth_password_too_short` | New password shorter than the minimum (8 by default) |
| `403` | `jwt_auth_reset_password_not_allowed` | A plugin refused the reset via `retrieve_password_user` |
| `500` | `jwt_auth_password_set_failed` | `wp_set_password` failed |

---

### 2.6 Any other WP REST endpoint (e.g. `GET /wp-json/wp/v2/posts`)

Authenticated calls just send the Bearer header:

```
Authorization: Bearer <token>
```

The plugin authenticates the user for the whole request, so normal WP permission
checks apply. Expired/revoked tokens get `401`/`403` and normal WP behaves as if the
user were not logged in.

---

## 3. React Native implementation

### 3.1 Auth client

```ts
// api.ts
const BASE = 'https://example.com';
const API  = `${BASE}/wp-json`;
const NS   = 'simple-jwt-authentication/v1';

let authToken: string | null = null;

export async function login(username: string, password: string) {
  const res = await fetch(`${API}/${NS}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password }),
  });

  if (res.status === 429) {
    throw new Error(`Too many attempts, retry after ${res.headers.get('Retry-After')}s`);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => null);
    throw new Error(err?.message ?? `Login failed (${res.status})`);
  }

  const data = await res.json();
  authToken = data.token;
  await SecureStore.setItemAsync('jwt', data.token); // or react-native-keychain
  await SecureStore.setItemAsync('jwt_expires', String(data.token_expires));
  return data;
}

export async function apiRequest(path: string, init: RequestInit = {}) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
  });

  if (res.status === 401 || res.status === 403) {
    // Token expired or revoked — clear it; app should re-prompt for credentials.
    await SecureStore.deleteItemAsync('jwt');
    authToken = null;
    throw new UnauthorizedError(res.status);
  }

  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res;
}

// Call on app foreground / boot: restore stored token, optionally hit
// `${API}/${NS}/token/validate` to confirm it still works.
```

Store the token in [expo-secure-store](https://docs.expo.dev/secure-store/) or
`react-native-keychain` — never plain AsyncStorage.

### 3.2 In-app password reset

```ts
// On a 401 (or from a "Forgot password?" screen):
export async function requestPasswordReset(username: string) {
  const res = await fetch(`${API}/${NS}/token/resetpassword`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username }),
  });
  // Always 200 — show the generic "check your email" message.
  return res.json();
}

export async function completePasswordReset(key: string, newPassword: string) {
  const res = await fetch(`${API}/${NS}/token/resetpassword/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ key, new_password: newPassword }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => null);
    throw new Error(err?.message ?? 'Reset failed');
  }

  // All old tokens are dead — force a fresh login.
  await SecureStore.deleteItemAsync('jwt');
  authToken = null;
  return res.json();
}
```

### 3.3 Deep link handling (the part v2.1.0 makes possible)

With the **Reset URL Template** set to `myapp://reset-password?key={key}&login={login}`,
the email link opens your app. Register the scheme and capture the params:

**iOS** — `Info.plist`: add `myapp` under `CFBundleURLTypes` → `CFBundleURLSchemes`.

**Android** — in `AndroidManifest.xml` inside `<application>`:

```xml
<activity ...>
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="myapp" android:host="reset-password" />
  </intent-filter>
</activity>
```

**App side** (Expo/react-navigation style):

```ts
useEffect(() => {
  const sub = Linking.addEventListener('url', ({ url }) => {
    if (!url?.startsWith('myapp://reset-password')) return;
    const params = new URL(url).searchParams;
    // Navigate to the new-password screen, prefilled with:
    //   key   = params.get('key')
    //   login = params.get('login')
    // That screen calls completePasswordReset(key, input) on submit.
    navigation.navigate('ResetPassword', {
      key: params.get('key') ?? undefined,
      login: params.get('login') ?? undefined,
    });
  });
  return () => sub.remove();
}, []);
```

Also call `Linking.getInitialURL()` on launch to handle a cold start from the email.

> **If you prefer HTTPS links** (universal links / app links) instead of a custom
> scheme: point the Reset URL Template at a page on your web app, e.g.
> `https://app.example.com/reset?key={key}&login={login}` — *and* configure
> `jwt_auth_cors_allow_origin` to your app domain if that page is a web app that
> also calls the API from a browser context. For a pure mobile flow, custom schemes
> are simpler.

### 3.4 CORS

Not applicable to the native fetch stack. Only relevant if you have a web build or
WebView hitting these endpoints — in that case enable CORS and pin
`jwt_auth_cors_allow_origin` to your origin (do not rely on `*` with credentials).

---

## 4. Security tuning checklist for production

- [ ] **Secret key**: 32+ random chars, unique per environment, never in client code
      (it is only used server-side).
- [ ] **Token lifetime**: default is 183 days. For a mobile app you likely want far
      less, e.g. mu-plugin:
      ```php
      add_filter('jwt_auth_expire', fn($exp, $iat) => $iat + 30 * DAY_IN_SECONDS, 10, 2);
      ```
      Handle the resulting 401s by re-authenticating (§3.1).
- [ ] **Reset key max age**: set 24 (or less) so a forwarded email stops working.
- [ ] **Rate limits** (`jwt_auth_login_rate_limit_max/_window`,
      `jwt_auth_reset_rate_limit_max/_window`): defaults assume direct
      `REMOTE_ADDR`. Behind a CDN/proxy all clients share one IP — raise the reset
      limits or have the proxy set the real client IP in `REMOTE_ADDR` (not
      `X-Forwarded-For`, which is deliberately untrusted).
- [ ] **HTTPS everywhere**; the token is the credential.
- [ ] On logout, call `/token/revoke` in addition to deleting the local token.

---

## 5. Quick smoke test from a terminal

```bash
# Login
TOKEN=$(curl -s -X POST https://example.com/wp-json/simple-jwt-authentication/v1/token \
  -d "username=admin&password=secret" | jq -r .token)

# Validate
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  https://example.com/wp-json/simple-jwt-authentication/v1/token/validate

# Use it on a normal WP endpoint
curl -s -H "Authorization: Bearer $TOKEN" \
  https://example.com/wp-json/wp/v2/users/me

# Request reset (generic 200)
curl -s -X POST https://example.com/wp-json/simple-jwt-authentication/v1/token/resetpassword \
  -d "username=admin"

# Complete reset (key comes from the email)
curl -s -X POST https://example.com/wp-json/simple-jwt-authentication/v1/token/resetpassword/complete \
  -d "key=<KEY>&new_password=newpassword123"

# Old token is now dead:
curl -s -H "Authorization: Bearer $TOKEN" \
  https://example.com/wp-json/wp/v2/users/me   # → 401/403
```
