<?php

declare(strict_types=1);

namespace SimpleJwtAuth;

use WP_User;

/**
 * Short numeric OTP used for in-app password reset (mobile / cross-device).
 *
 * The plain code is emailed once and never stored. Only a hash + expiry +
 * attempt counter live in user meta. A successful verification (or a fresh
 * request) clears the record.
 */
final class PasswordResetCode
{
    public const META_KEY = 'jwt_reset_otp';

    /** Default code length (digits only). */
    private const DEFAULT_LENGTH = 6;

    /** Default lifetime in seconds (30 minutes). */
    private const DEFAULT_TTL = 30 * MINUTE_IN_SECONDS;

    /** Max wrong guesses before the code is burned. */
    private const DEFAULT_MAX_ATTEMPTS = 5;

    /**
     * Generate a fresh OTP for the user, store its hash, and return the plain
     * code for the email body. Any previous unused code is replaced.
     */
    public static function issue(WP_User $user): string
    {
        $length = max(4, min(8, (int) apply_filters('jwt_auth_reset_code_length', self::DEFAULT_LENGTH, $user)));
        $ttl    = max(60, (int) apply_filters('jwt_auth_reset_code_ttl', self::DEFAULT_TTL, $user));

        $max = 10 ** $length;
        $code = str_pad((string) random_int(0, $max - 1), $length, '0', STR_PAD_LEFT);

        $payload = [
            'hash'     => self::hash($code, $user->ID),
            'expires'  => time() + $ttl,
            'attempts' => 0,
        ];

        update_user_meta($user->ID, self::META_KEY, $payload);

        return $code;
    }

    /**
     * Verify a submitted code for the given user.
     *
     * @return true|\WP_Error True on match. WP_Error codes:
     *   - jwt_auth_invalid_code  (missing / wrong / expired / burned)
     *   - jwt_auth_too_many_attempts (per-code attempt budget exhausted)
     */
    public static function verify(WP_User $user, string $code): true|\WP_Error
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if ($code === '' || !ctype_digit($code)) {
            return new \WP_Error(
                'jwt_auth_invalid_code',
                __('The reset code is invalid or has expired.', 'simple-jwt-authentication'),
                ['status' => 400]
            );
        }

        $payload = get_user_meta($user->ID, self::META_KEY, true);
        if (!is_array($payload) || empty($payload['hash']) || empty($payload['expires'])) {
            return new \WP_Error(
                'jwt_auth_invalid_code',
                __('The reset code is invalid or has expired.', 'simple-jwt-authentication'),
                ['status' => 400]
            );
        }

        $maxAttempts = max(1, (int) apply_filters('jwt_auth_reset_code_max_attempts', self::DEFAULT_MAX_ATTEMPTS, $user));
        $attempts    = (int) ($payload['attempts'] ?? 0);

        if ($attempts >= $maxAttempts) {
            self::clear($user);

            return new \WP_Error(
                'jwt_auth_too_many_attempts',
                __('Too many attempts. Please request a new code.', 'simple-jwt-authentication'),
                ['status' => 429]
            );
        }

        if ((int) $payload['expires'] < time()) {
            self::clear($user);

            return new \WP_Error(
                'jwt_auth_invalid_code',
                __('The reset code is invalid or has expired.', 'simple-jwt-authentication'),
                ['status' => 400]
            );
        }

        if (!hash_equals((string) $payload['hash'], self::hash($code, $user->ID))) {
            $payload['attempts'] = $attempts + 1;
            update_user_meta($user->ID, self::META_KEY, $payload);

            if ($payload['attempts'] >= $maxAttempts) {
                self::clear($user);

                return new \WP_Error(
                    'jwt_auth_too_many_attempts',
                    __('Too many attempts. Please request a new code.', 'simple-jwt-authentication'),
                    ['status' => 429]
                );
            }

            return new \WP_Error(
                'jwt_auth_invalid_code',
                __('The reset code is invalid or has expired.', 'simple-jwt-authentication'),
                ['status' => 400]
            );
        }

        return true;
    }

    /**
     * Remove any stored OTP for the user (after success or burn-out).
     */
    public static function clear(WP_User $user): void
    {
        delete_user_meta($user->ID, self::META_KEY);
    }

    /**
     * HMAC of the plain code keyed by WP salts + user id so hashes aren't
     * portable across sites or users.
     */
    private static function hash(string $code, int $userId): string
    {
        return hash_hmac('sha256', $code . '|' . $userId, wp_salt('auth'));
    }
}
