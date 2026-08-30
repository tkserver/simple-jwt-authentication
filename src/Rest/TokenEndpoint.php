<?php

declare(strict_types=1);

namespace SimpleJwtAuth\Rest;

use SimpleJwtAuth\Config;
use SimpleJwtAuth\PasswordResetCode;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Handles the REST endpoint callbacks.
 */
final class TokenEndpoint
{
    private readonly TokenService $tokenService;

    public function __construct(TokenService $tokenService)
    {
        $this->tokenService = $tokenService;

        // Only override core's reset-key expiration when the admin has set a
        // non-zero value; 0 defers to core's own default (24h as of WP 5.7+).
        add_filter('password_reset_expiration', function (int $default): int {
            $configured = Config::getResetKeyMaxAge();
            return $configured > 0 ? $configured : $default;
        });
    }

    /**
     * POST /token — authenticate and return a JWT.
     */
    public function generateToken(WP_REST_Request $request): WP_REST_Response
    {
        if (Config::getSecretKey() === null) {
            return $this->errorResponse(
                'jwt_auth_bad_config',
                __('JWT is not configured properly. The key is missing.', 'simple-jwt-authentication'),
                503
            );
        }

        [$maxAttempts, $window] = $this->tokenService->getLoginRateLimit();

        if ($this->tokenService->isRateLimited('login', $maxAttempts, $window)) {
            $response = $this->errorResponse(
                'jwt_auth_too_many_attempts',
                __('Too many login attempts. Please try again later.', 'simple-jwt-authentication'),
                429
            );
            $response->header('Retry-After', (string) $window);

            return $response;
        }

        $username = (string) $request->get_param('username');
        $password = (string) $request->get_param('password');

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            // Count failures per IP; the counter resets on a successful login.
            $this->tokenService->registerRateLimitHit('login', $window);
            $code = $user->get_error_code();
            return $this->errorResponse(
                "[jwt_auth] $code",
                $user->get_error_message($code),
                401
            );
        }

        $this->tokenService->resetRateLimit('login');

        try {
            $data = $this->tokenService->generateToken($user);
        } catch (\RuntimeException $e) {
            return $this->errorResponse('jwt_auth_bad_config', $e->getMessage(), 503);
        }

        return new WP_REST_Response($data, 200);
    }

    /**
     * POST /token/validate — check if the Bearer token is valid.
     */
    public function validateToken(WP_REST_Request $request): WP_REST_Response
    {
        $token = $this->tokenService->validateToken();

        if (is_wp_error($token)) {
            return $this->errorFromJwt($token);
        }

        return new WP_REST_Response([
            'code' => 'jwt_auth_valid_token',
            'data' => ['status' => 200],
        ], 200);
    }

    /**
     * POST /token/revoke — revoke the current Bearer token.
     */
    public function revokeToken(WP_REST_Request $request): WP_REST_Response
    {
        $result = $this->tokenService->revokeCurrentToken();

        $status = match($result['code']) {
            'jwt_auth_revoked_token'       => 200,
            'jwt_auth_no_token_to_revoke'  => 404,
            default                         => 403,
        };

        return new WP_REST_Response($result, $status);
    }

    /**
     * POST /token/resetpassword — send a password reset email.
     *
     * Always returns the same generic 200 response regardless of whether the
     * account exists or reset is allowed, mirroring WP core's
     * `wp-login.php?action=lostpassword` behavior to prevent username
     * enumeration and email-sending abuse.
     */
    public function resetPassword(WP_REST_Request $request): WP_REST_Response
    {
        $username = trim((string) $request->get_param('username'));

        if ($username !== '') {
            $this->attemptPasswordReset($username);
        }

        return $this->resetPasswordSuccess();
    }

    /**
     * POST /token/resetpassword — always-200 response shared by all outcomes.
     */
    private function resetPasswordSuccess(): WP_REST_Response
    {
        return new WP_REST_Response([
            'code'    => 'jwt_auth_password_reset',
            'message' => __(
                'If the username or email address exists on this site, a password reset code has been sent.',
                'simple-jwt-authentication'
            ),
            'data'    => ['status' => 200],
        ], 200);
    }

    private function attemptPasswordReset(string $username): void
    {
        $user = str_contains($username, '@')
            ? get_user_by('email', $username)
            : get_user_by('login', $username);

        if (!$user) {
            // No user: do nothing, and do not fire the lost-password actions.
            return;
        }

        $userLogin = $user->user_login;
        $userEmail = $user->user_email;

        // Fires before the WP core check/hooks below; mirrors core's own
        // lostpassword_post signal that a reset was requested for this user.
        do_action('lostpassword_post');

        $allowed = apply_filters('allow_password_reset', true, $user->ID);
        if (!$allowed || is_wp_error($allowed)) {
            return;
        }

        // Throttle actual email sends per IP. When over budget we silently
        // skip the send (the caller still gets the uniform success response).
        [$maxEmails, $window] = $this->tokenService->getPasswordResetRateLimit();
        if ($this->tokenService->isRateLimited('password_reset', $maxEmails, $window)) {
            return;
        }

        // Primary path for mobile / cross-device: a short numeric OTP the user
        // types back into the app. Hash only is stored; plain code is emailed.
        $code = PasswordResetCode::issue($user);

        // Also refresh the core WP reset key so a deep-link / web fallback
        // still works if the site has a reset URL template configured.
        $key = get_password_reset_key($user);
        if (is_wp_error($key)) {
            $key = '';
        }

        $message  = __('Someone requested that the password be reset for the following account:', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= network_home_url('/') . "\r\n\r\n";
        $message .= sprintf(__('Username: %s', 'simple-jwt-authentication'), $userLogin) . "\r\n\r\n";

        $requestIp = $this->getClientIp();
        if ($requestIp !== '') {
            $message .= sprintf(
                /* translators: %s: IP address */
                __('This password reset request originated from the IP address %s.', 'simple-jwt-authentication'),
                $requestIp
            ) . "\r\n\r\n";
        }

        $message .= __('If this was a mistake, just ignore this email and nothing will happen.', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= __('Enter this code in the app to choose a new password:', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= $code . "\r\n\r\n";
        $message .= __('This code expires in 30 minutes and can only be used once.', 'simple-jwt-authentication') . "\r\n";

        // Optional deep-link / web fallback when a reset URL template (or the
        // default wp-login.php link) is available.
        if (is_string($key) && $key !== '') {
            $fallbackUrl = $this->applyResetUrlFilters(
                network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($userLogin), 'login'),
                $user,
                $key
            );
            if ($fallbackUrl !== '') {
                $message .= "\r\n" . __('Or open this link on a device with the app installed:', 'simple-jwt-authentication') . "\r\n\r\n";
                $message .= '<' . $fallbackUrl . ">\r\n";
            }
        }

        $title = sprintf(
            /* translators: %s: site name */
            __('[%s] Password Reset Code', 'simple-jwt-authentication'),
            is_multisite() ? (string) ($GLOBALS['current_site']->site_name ?? '') : wp_specialchars_decode(get_option('blogname', ''), ENT_QUOTES)
        );

        $title   = apply_filters('retrieve_password_title', $title);
        $message = apply_filters('retrieve_password_message', $message, $key, $userLogin, $user);
        // Extra filter with the OTP so themes can customize without parsing the body.
        $message = apply_filters('jwt_auth_reset_password_message', $message, $code, $user, $key);

        if (!$message || !wp_mail($userEmail, $title, $message, ['Content-Type: text/plain; charset=UTF-8'])) {
            // Mail failed: drop the OTP so a stuck code can't be used later.
            PasswordResetCode::clear($user);

            return;
        }

        $this->tokenService->registerRateLimitHit('password_reset', $window);
    }

    /**
     * POST /token/resetpassword/complete — set a new password.
     *
     * Accepts either:
     *   - code + login + new_password  (6-digit OTP from the email — preferred)
     *   - key  + login + new_password  (legacy WP reset key / deep link)
     */
    public function completeResetPassword(WP_REST_Request $request): WP_REST_Response
    {
        $code        = trim((string) $request->get_param('code'));
        $key         = (string) $request->get_param('key');
        $login       = $this->resolveLoginParam($request);
        $newPassword = (string) $request->get_param('new_password');

        if ($login === '' || ($code === '' && $key === '')) {
            return $this->errorResponse(
                'jwt_auth_invalid_code',
                __('Reset code or login not specified.', 'simple-jwt-authentication'),
                400
            );
        }

        [$maxAttempts, $window] = $this->tokenService->getResetCompleteRateLimit();
        if ($this->tokenService->isRateLimited('reset_complete', $maxAttempts, $window)) {
            $response = $this->errorResponse(
                'jwt_auth_too_many_attempts',
                __('Too many attempts. Please try again later.', 'simple-jwt-authentication'),
                429
            );
            $response->header('Retry-After', (string) $window);

            return $response;
        }
        $this->tokenService->registerRateLimitHit('reset_complete', $window);

        $minLength = (int) apply_filters(
            'jwt_auth_reset_password_min_length',
            8,
            $code !== '' ? $code : $key,
            $newPassword
        );
        if (mb_strlen($newPassword) < $minLength) {
            return $this->errorResponse(
                'jwt_auth_password_too_short',
                sprintf(
                    /* translators: %d: minimum password length */
                    __('Password must be at least %d characters long.', 'simple-jwt-authentication'),
                    $minLength
                ),
                400
            );
        }

        if ($code !== '') {
            return $this->completeWithCode($login, $code, $newPassword);
        }

        return $this->completeWithKey($login, $key, $newPassword);
    }

    /**
     * Complete a reset using the emailed numeric OTP.
     */
    private function completeWithCode(string $login, string $code, string $newPassword): WP_REST_Response
    {
        $user = get_user_by('login', $login);
        if (!$user) {
            // Also accept email-as-login for convenience (app may pass identity).
            $user = str_contains($login, '@') ? get_user_by('email', $login) : false;
        }
        if (!$user) {
            return $this->errorResponse(
                'jwt_auth_invalid_code',
                __('The reset code is invalid or has expired.', 'simple-jwt-authentication'),
                400
            );
        }

        $verified = PasswordResetCode::verify($user, $code);
        if (is_wp_error($verified)) {
            $status = (int) ($verified->get_error_data()['status'] ?? 400);
            $response = $this->errorResponse(
                $verified->get_error_code(),
                $verified->get_error_message(),
                $status
            );
            if ($status === 429) {
                $response->header('Retry-After', '900');
            }

            return $response;
        }

        $user = apply_filters('retrieve_password_user', $user, $code);
        if (is_wp_error($user)) {
            return $this->errorResponse(
                'jwt_auth_reset_password_not_allowed',
                $user->get_error_message(),
                403
            );
        }

        // Consume the OTP before writing the password so a concurrent retry
        // cannot reuse the same code after we succeed.
        PasswordResetCode::clear($user);

        // Also burn any core WP activation key so deep-link leftovers die too.
        global $wpdb;
        $wpdb->update($wpdb->users, ['user_activation_key' => ''], ['ID' => $user->ID]);

        return $this->finalizePasswordReset($user, $newPassword);
    }

    /**
     * Complete a reset using the legacy WP reset key (deep link / web).
     */
    private function completeWithKey(string $login, string $key, string $newPassword): WP_REST_Response
    {
        // Storage/hashing/expiry are entirely core's (WP 6.8+ hashed keys,
        // 5.7+ default 24h expiry via the password_reset_expiration filter
        // registered in the constructor).
        $user = check_password_reset_key($key, $login);

        if (is_wp_error($user)) {
            return $this->errorResponse(
                'jwt_auth_invalid_key',
                __('The password reset key is invalid or has expired.', 'simple-jwt-authentication'),
                400
            );
        }

        $user = apply_filters('retrieve_password_user', $user, $key);
        if (is_wp_error($user)) {
            return $this->errorResponse(
                'jwt_auth_reset_password_not_allowed',
                $user->get_error_message(),
                403
            );
        }

        // Atomically consume the key: only one concurrent request can win the
        // compare-and-clear, closing the race where two requests both pass
        // check_password_reset_key() before either writes the new password.
        global $wpdb;
        $consumed = $wpdb->query($wpdb->prepare(
            "UPDATE $wpdb->users SET user_activation_key = '' WHERE ID = %d AND user_activation_key = %s",
            $user->ID,
            $user->user_activation_key
        ));
        if ($consumed !== 1) {
            return $this->errorResponse(
                'jwt_auth_invalid_key',
                __('The password reset key is invalid or has expired.', 'simple-jwt-authentication'),
                400
            );
        }

        PasswordResetCode::clear($user);

        return $this->finalizePasswordReset($user, $newPassword);
    }

    /**
     * Shared success path after a key or code has been validated and consumed.
     */
    private function finalizePasswordReset(\WP_User $user, string $newPassword): WP_REST_Response
    {
        // wp_set_password() is void as of modern WP (returns nothing). Calling
        // it and testing the return value always looked like failure.
        try {
            wp_set_password($newPassword, $user->ID);
        } catch (\Throwable $e) {
            return $this->errorResponse(
                'jwt_auth_password_set_failed',
                __('The new password could not be set.', 'simple-jwt-authentication'),
                500
            );
        }

        // Sanity: hash actually landed (defends against broken pluggable overrides).
        $fresh = get_userdata($user->ID);
        if (!$fresh || !wp_check_password($newPassword, $fresh->user_pass, $user->ID)) {
            return $this->errorResponse(
                'jwt_auth_password_set_failed',
                __('The new password could not be set.', 'simple-jwt-authentication'),
                500
            );
        }

        // Invalidate every session token issued before the reset.
        $this->tokenService->revokeAllUserTokens($user->ID);

        do_action('password_reset', $user, $newPassword);

        $this->sendResetConfirmationEmail($user);

        return new WP_REST_Response([
            'code'    => 'jwt_auth_password_reset_complete',
            'message' => __('Your password has been reset. You can now sign in with your new password.', 'simple-jwt-authentication'),
            'data'    => ['status' => 200],
        ], 200);
    }

    /**
     * Notify the user that their password was changed (opt-in; failures ignored).
     */
    private function sendResetConfirmationEmail(\WP_User $user): void
    {
        if (!apply_filters('jwt_auth_send_reset_confirmation_email', true, $user)) {
            return;
        }

        $message = __('Your password was successfully changed on this site:', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= network_home_url('/') . "\r\n";

        $title = sprintf(
            /* translators: %s: site name */
            __('[%s] Your password has been changed', 'simple-jwt-authentication'),
            wp_specialchars_decode(get_option('blogname', ''), ENT_QUOTES)
        );

        $message = apply_filters('jwt_auth_reset_confirmation_message', $message, $user);
        $title   = apply_filters('jwt_auth_reset_confirmation_title', $title, $user);

        if ($message !== '') {
            wp_mail($user->user_email, $title, $message, ['Content-Type: text/plain; charset=UTF-8']);
        }
    }

    /**
     * Allow the emailed reset link to be replaced (e.g. a mobile app deep link).
     *
     * A configured "Reset URL Template" (see Settings → Simple JWT
     * Authentication) is applied first and replaces the default
     * wp-login.php?action=rp link entirely, so app users never land on the
     * web reset form. The {key} and {login} placeholders are filled in.
     */
    private function applyResetUrlFilters(string $url, \WP_User $user, string $key): string
    {
        $template = Config::getResetUrlTemplate();
        if ($template !== null) {
            $url = strtr($template, [
                '{key}'   => rawurlencode($key),
                '{login}' => rawurlencode($user->user_login),
            ]);
        }

        $url = apply_filters('jwt_auth_reset_url', $url, $user, $key);
        $url = apply_filters('lostpassword_url', $url, $key);
        return $url;
    }

    /**
     * Resolve the account identity from either plain `login` or base64 `account`.
     * Mobile clients send `account` when the identity is an email address so the
     * POST body never contains "@" (CleanTalk and similar will 200-block those).
     */
    private function resolveLoginParam(WP_REST_Request $request): string
    {
        $login = trim((string) $request->get_param('login'));
        if ($login !== '') {
            return $login;
        }

        $account = trim((string) $request->get_param('account'));
        if ($account === '') {
            return '';
        }

        // Accept standard and URL-safe base64.
        $normalized = strtr($account, '-_', '+/');
        $pad = strlen($normalized) % 4;
        if ($pad > 0) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if (!is_string($decoded) || $decoded === '') {
            return '';
        }

        // Reject binary junk; identities are plain UTF-8 login/email strings.
        if (!preg_match('//u', $decoded) || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $decoded)) {
            return '';
        }

        return trim($decoded);
    }

    private function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        return is_string($ip) ? $ip : '';
    }

    private function errorResponse(string $code, string $message, int $status): WP_REST_Response
    {
        return new WP_REST_Response([
            'code'    => $code,
            'message' => $message,
            'data'    => ['status' => $status],
        ], $status);
    }

    /**
     * Map a TokenService WP_Error (English, untranslated — safe for the
     * determine_current_user path) into a translated REST error response.
     */
    private function errorFromJwt(WP_Error $error): WP_REST_Response
    {
        $code   = $error->get_error_code();
        $status = (int) ($error->get_error_data()['status'] ?? 401);

        $message = match ($code) {
            'jwt_auth_no_auth_header' => __('Authorization header not found.', 'simple-jwt-authentication'),
            'jwt_auth_bad_auth_header' => __('Authorization header malformed.', 'simple-jwt-authentication'),
            'jwt_auth_bad_config' => __('JWT is not configured properly. The key is missing.', 'simple-jwt-authentication'),
            'jwt_auth_bad_iss' => __('The issuer does not match this server.', 'simple-jwt-authentication'),
            'jwt_auth_bad_request' => __('User ID not found in the token.', 'simple-jwt-authentication'),
            'jwt_auth_token_revoked' => __('Token has been revoked.', 'simple-jwt-authentication'),
            // Exception messages (expired/invalid) stay as-is from firebase/php-jwt.
            default => $error->get_error_message(),
        };

        return $this->errorResponse($code, $message, $status);
    }
}
