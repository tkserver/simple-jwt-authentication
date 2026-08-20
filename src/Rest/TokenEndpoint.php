<?php

declare(strict_types=1);

namespace SimpleJwtAuth\Rest;

use SimpleJwtAuth\Config;
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
            return $this->errorResponse(
                $token->get_error_code(),
                $token->get_error_message(),
                $token->get_error_data()['status'] ?? 401
            );
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
                'If the username or email address exists on this site, a password reset link has been sent.',
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

        do_action('lostpassword_post');
        do_action('retrieve_password', $userLogin);

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

        $key = $this->generateOrGetResetKey($userLogin);

        $message  = __('Someone requested that the password be reset for the following account:', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= network_home_url('/') . "\r\n\r\n";
        $message .= sprintf(__('Username: %s', 'simple-jwt-authentication'), $userLogin) . "\r\n\r\n";
        $message .= __('If this was a mistake, just ignore this email and nothing will happen.', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= __('To reset your password, visit the following address:', 'simple-jwt-authentication') . "\r\n\r\n";
        $message .= '<' . network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($userLogin), 'login') . ">\r\n";

        $title = sprintf(
            /* translators: %s: site name */
            __('[%s] Password Reset', 'simple-jwt-authentication'),
            is_multisite() ? (string) ($GLOBALS['current_site']->site_name ?? '') : wp_specialchars_decode(get_option('blogname', ''), ENT_QUOTES)
        );

        $title   = apply_filters('retrieve_password_title', $title);
        $message = apply_filters('retrieve_password_message', $message, $key);

        if (!$message || !wp_mail($userEmail, $title, $message)) {
            return;
        }

        $this->tokenService->registerRateLimitHit('password_reset', $window);
    }

    private function generateOrGetResetKey(string $userLogin): string
    {
        global $wpdb;

        $key = $wpdb->get_var($wpdb->prepare(
            "SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s",
            $userLogin
        ));

        if (empty($key)) {
            $key = wp_generate_password(20, false);
            do_action('retrieve_password_key', $userLogin, $key);
            $wpdb->update($wpdb->users, ['user_activation_key' => $key], ['user_login' => $userLogin]);
        }

        return $key;
    }

    private function errorResponse(string $code, string $message, int $status): WP_REST_Response
    {
        return new WP_REST_Response([
            'code'    => $code,
            'message' => $message,
            'data'    => ['status' => $status],
        ], $status);
    }
}
