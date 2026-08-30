<?php

declare(strict_types=1);

namespace SimpleJwtAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\UnexpectedValueException;
use WP_Error;
use WP_User;

/**
 * Handles JWT encoding, decoding, validation, and revocation.
 */
final class TokenService
{
    private const ALGORITHM = 'HS256';
    private const TOKEN_LIFETIME_SECONDS = DAY_IN_SECONDS * 183;

    /** Soft cap on concurrent stored sessions per user (oldest dropped first). */
    private const MAX_TOKENS_PER_USER = 50;

    private const RATE_LIMIT_LOGIN_MAX = 10;
    private const RATE_LIMIT_LOGIN_WINDOW = 15 * MINUTE_IN_SECONDS;
    private const RATE_LIMIT_PASSWORD_RESET_MAX = 5;
    private const RATE_LIMIT_PASSWORD_RESET_WINDOW = 15 * MINUTE_IN_SECONDS;
    private const RATE_LIMIT_RESET_COMPLETE_MAX = 10;
    private const RATE_LIMIT_RESET_COMPLETE_WINDOW = 15 * MINUTE_IN_SECONDS;

    private ?WP_Error $jwtError = null;

    /**
     * Generate a signed JWT for the given user.
     *
     * @return array{token: string, user_id: string, user_email: string, user_nicename: string, user_display_name: string, token_expires: int}
     */
    public function generateToken(WP_User $user): array
    {
        $secretKey = Config::getSecretKey();
        if ($secretKey === null) {
            throw new \RuntimeException('JWT secret key is not configured.');
        }

        $issuedAt  = time();
        $notBefore = apply_filters('jwt_auth_not_before', $issuedAt);
        $expire    = apply_filters('jwt_auth_expire', $issuedAt + self::TOKEN_LIFETIME_SECONDS, $issuedAt);
        $uuid      = wp_generate_uuid4();

        // Issuer must match tokens already on devices (v1 used get_bloginfo('url')).
        // Changing this without a filter would mass-revoke every stored mobile session.
        $payload = [
            'uuid'  => $uuid,
            'iss'   => apply_filters('jwt_auth_token_iss', get_bloginfo('url')),
            'iat'   => $issuedAt,
            'nbf'   => $notBefore,
            'exp'   => $expire,
            'data'  => [
                'user' => [
                    'id' => $user->ID,
                ],
            ],
        ];

        $payload = apply_filters('jwt_auth_token_before_sign', $payload, $user);
        $token   = JWT::encode($payload, $secretKey, self::ALGORITHM);

        $this->storeTokenMetadata($user->ID, $uuid, $issuedAt, $expire);

        // Keep the login JSON shape identical to v1 for the mobile app:
        // - user_id as a *string* (v1 used $user->data->ID from the DB).
        //   React Native AsyncStorage.setItem() throws if given a number, which
        //   crashes the app immediately after a successful login.
        // - token_expires remains an int (unix timestamp); the app does not
        //   AsyncStorage it on login.
        return apply_filters('jwt_auth_token_before_dispatch', [
            'token'             => $token,
            'user_id'           => (string) $user->ID,
            'user_email'        => (string) $user->user_email,
            'user_nicename'     => (string) $user->user_nicename,
            'user_display_name' => (string) $user->display_name,
            'token_expires'     => (int) $expire,
        ], $user);
    }

    /**
     * Validate the Bearer token from the current request.
     *
     * IMPORTANT: Error messages here are intentionally NOT passed through __().
     * This method runs on the `determine_current_user` filter (middleware). Calling
     * translation APIs can resolve the user locale via wp_get_current_user(), which
     * re-enters determine_current_user and exhausts memory (infinite recursion).
     * Translate at the REST response boundary instead (TokenEndpoint).
     *
     * @return \stdClass|WP_Error The decoded token payload, or a WP_Error.
     */
    public function validateToken(bool $forMiddleware = false): \stdClass|WP_Error
    {
        $authHeader = $this->getAuthHeader();
        if ($authHeader === null) {
            return new WP_Error(
                'jwt_auth_no_auth_header',
                'Authorization header not found.',
                ['status' => 401]
            );
        }

        if (!preg_match('/^Bearer\s+(\S+)$/', $authHeader, $matches)) {
            return new WP_Error(
                'jwt_auth_bad_auth_header',
                'Authorization header malformed.',
                ['status' => 401]
            );
        }

        $secretKey = Config::getSecretKey();
        if ($secretKey === null) {
            return new WP_Error(
                'jwt_auth_bad_config',
                'JWT is not configured properly. The key is missing.',
                ['status' => 503]
            );
        }

        try {
            $key   = new Key($secretKey, self::ALGORITHM);
            $token = JWT::decode($matches[1], $key);
        } catch (ExpiredException $e) {
            return new WP_Error('jwt_auth_expired_token', $e->getMessage(), ['status' => 401]);
        } catch (BeforeValidException $e) {
            return new WP_Error('jwt_auth_not_yet_valid', $e->getMessage(), ['status' => 401]);
        } catch (SignatureInvalidException $e) {
            return new WP_Error('jwt_auth_invalid_token', $e->getMessage(), ['status' => 401]);
        } catch (UnexpectedValueException $e) {
            return new WP_Error('jwt_auth_invalid_token', $e->getMessage(), ['status' => 401]);
        } catch (\Throwable $e) {
            return new WP_Error('jwt_auth_invalid_token', $e->getMessage(), ['status' => 401]);
        }

        // Must match generateToken / v1: get_bloginfo('url'). Do not call __() here.
        $expectedIss = apply_filters('jwt_auth_token_iss', get_bloginfo('url'));
        if (!property_exists($token, 'iss') || $expectedIss !== $token->iss) {
            return new WP_Error(
                'jwt_auth_bad_iss',
                'The issuer does not match this server.',
                ['status' => 403]
            );
        }

        if (!isset($token->data->user->id)) {
            return new WP_Error(
                'jwt_auth_bad_request',
                'User ID not found in the token.',
                ['status' => 403]
            );
        }

        $userId    = (int) $token->data->user->id;
        $tokenUuid = (string) ($token->uuid ?? '');

        if ($tokenUuid === '' || !$this->verifyTokenUuid($userId, $tokenUuid, $forMiddleware)) {
            return new WP_Error(
                'jwt_auth_token_revoked',
                'Token has been revoked.',
                ['status' => 403]
            );
        }

        return $token;
    }

    /**
     * Revoke the current Bearer token.
     *
     * @return array{code: string, data: array{status: int}}
     */
    public function revokeCurrentToken(): array
    {
        $token = $this->validateToken();
        if (is_wp_error($token)) {
            $code = $token->get_error_code();
            return [
                'code' => $code,
                'data' => ['status' => $token->get_error_data()['status'] ?? 403],
            ];
        }

        $userId    = (int) $token->data->user->id;
        $tokenUuid = (string) $token->uuid;
        $tokens    = get_user_meta($userId, 'jwt_data', true);

        if (is_array($tokens)) {
            foreach ($tokens as $key => $tokenData) {
                if (hash_equals($tokenData['uuid'], $tokenUuid)) {
                    unset($tokens[$key]);
                    update_user_meta($userId, 'jwt_data', $tokens);
                    return [
                        'code' => 'jwt_auth_revoked_token',
                        'data' => ['status' => 200],
                    ];
                }
            }
        }

        return [
            'code' => 'jwt_auth_no_token_to_revoke',
            'data' => ['status' => 404],
        ];
    }

    /**
     * Get any stored JWT error (for middleware → rest_pre_dispatch handoff).
     */
    public function getJwtError(): ?WP_Error
    {
        return $this->jwtError;
    }

    /**
     * Store the JWT error to be surfaced by the rest_pre_dispatch filter.
     */
    public function setJwtError(?WP_Error $error): void
    {
        $this->jwtError = $error;
    }

    /**
     * Remove expired tokens from a user's stored metadata.
     */
    public function removeExpiredTokens(int $userId): int
    {
        $tokens = get_user_meta($userId, 'jwt_data', true);
        if (!is_array($tokens)) {
            return 0;
        }

        $pruned = [];
        $now      = time();
        $removed  = 0;

        foreach ($tokens as $tokenData) {
            if (($tokenData['expires'] ?? 0) < $now) {
                $removed++;
            } else {
                $pruned[] = $tokenData;
            }
        }

        if ($removed > 0) {
            update_user_meta($userId, 'jwt_data', $pruned);
        }

        return $removed;
    }

    /**
     * Revoke every JWT stored for a user (e.g. after a password reset).
     *
     * @return int Number of tokens removed (0 if none were stored).
     */
    public function revokeAllUserTokens(int $userId): int
    {
        $tokens = get_user_meta($userId, 'jwt_data', true);
        delete_user_meta($userId, 'jwt_data');
        return is_array($tokens) ? count($tokens) : 0;
    }

    private function getAuthHeader(): ?string
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (empty($auth)) {
            $auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        }
        return $auth !== '' ? $auth : null;
    }

    private function storeTokenMetadata(int $userId, string $uuid, int $issuedAt, int $expires): void
    {
        $jwtData = get_user_meta($userId, 'jwt_data', true);
        if (!is_array($jwtData)) {
            $jwtData = [];
        }

        // Drop expired entries before appending so growth is bounded by active sessions.
        $now     = time();
        $jwtData = array_values(array_filter(
            $jwtData,
            static fn($row): bool => is_array($row) && (int) ($row['expires'] ?? 0) >= $now
        ));

        $jwtData[] = [
            'uuid'      => $uuid,
            'issued_at' => $issuedAt,
            'expires'   => $expires,
            'ip'        => $this->getClientIp(),
            'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'last_used' => $now,
        ];

        $maxTokens = (int) apply_filters('jwt_auth_max_tokens_per_user', self::MAX_TOKENS_PER_USER);
        if ($maxTokens > 0 && count($jwtData) > $maxTokens) {
            // Keep the most recently issued sessions.
            usort(
                $jwtData,
                static fn(array $a, array $b): int => ((int) ($b['issued_at'] ?? 0)) <=> ((int) ($a['issued_at'] ?? 0))
            );
            $jwtData = array_slice($jwtData, 0, $maxTokens);
        }

        update_user_meta($userId, 'jwt_data', apply_filters('simple_jwt_auth_save_user_data', $jwtData));
    }

    private function verifyTokenUuid(int $userId, string $tokenUuid, bool $updateLastUsed): bool
    {
        $tokens = get_user_meta($userId, 'jwt_data', true);
        if (!is_array($tokens)) {
            return false;
        }

        // `last_used` is only worth re-writing periodically; the stored value is
        // "approximate" within this window to avoid a user-meta write per request.
        $updateInterval = (int) apply_filters('jwt_auth_last_used_update_interval', HOUR_IN_SECONDS);

        $now       = time();
        $valid     = false;
        $changed   = false;
        $filtered  = [];

        foreach ($tokens as $tokenData) {
            // Prune expired entries while we already have the list in memory.
            if ((int) ($tokenData['expires'] ?? 0) < $now) {
                continue;
            }

            if (hash_equals((string) ($tokenData['uuid'] ?? ''), $tokenUuid)) {
                $valid = true;

                if ($updateLastUsed) {
                    $lastUsed = (int) ($tokenData['last_used'] ?? 0);
                    if ($now - $lastUsed >= $updateInterval) {
                        $tokenData['last_used'] = $now;
                        $tokenData['ip']        = $this->getClientIp();
                        $tokenData['ua']        = $_SERVER['HTTP_USER_AGENT'] ?? '';
                        $changed                = true;
                    }
                }
            }

            $filtered[] = $tokenData;
        }

        if ($changed || count($filtered) < count($tokens)) {
            update_user_meta($userId, 'jwt_data', $filtered);
        }

        return $valid;
    }

    /**
     * Whether the current IP has exhausted the rate-limit budget for a bucket.
     */
    public function isRateLimited(string $bucket, int $maxAttempts, int $windowSeconds): bool
    {
        return $this->getRateLimitCount($bucket) >= $maxAttempts;
    }

    /**
     * Record one rate-limit hit for the current IP (e.g. a failed login).
     */
    public function registerRateLimitHit(string $bucket, int $windowSeconds): void
    {
        $key = $this->rateLimitKey($bucket);
        set_transient($key, $this->getRateLimitCount($bucket) + 1, $windowSeconds);
    }

    /**
     * Clear the rate-limit counter (e.g. after a successful login).
     */
    public function resetRateLimit(string $bucket): void
    {
        delete_transient($this->rateLimitKey($bucket));
    }

    /**
     * Login rate limit: filterable max attempts / window per IP.
     */
    public function getLoginRateLimit(): array
    {
        $max    = (int) apply_filters('jwt_auth_login_rate_limit_max', self::RATE_LIMIT_LOGIN_MAX);
        $window = (int) apply_filters('jwt_auth_login_rate_limit_window', self::RATE_LIMIT_LOGIN_WINDOW);

        return [max(1, $max), max(10, $window)];
    }

    /**
     * Password reset rate limit: filterable max emails / window per IP.
     */
    public function getPasswordResetRateLimit(): array
    {
        $max    = (int) apply_filters('jwt_auth_reset_rate_limit_max', self::RATE_LIMIT_PASSWORD_RESET_MAX);
        $window = (int) apply_filters('jwt_auth_reset_rate_limit_window', self::RATE_LIMIT_PASSWORD_RESET_WINDOW);

        return [max(1, $max), max(10, $window)];
    }

    /**
     * Reset-complete rate limit: filterable max attempts / window per IP.
     */
    public function getResetCompleteRateLimit(): array
    {
        $max    = (int) apply_filters('jwt_auth_reset_complete_rate_limit_max', self::RATE_LIMIT_RESET_COMPLETE_MAX);
        $window = (int) apply_filters('jwt_auth_reset_complete_rate_limit_window', self::RATE_LIMIT_RESET_COMPLETE_WINDOW);

        return [max(1, $max), max(10, $window)];
    }

    private function getRateLimitCount(string $bucket): int
    {
        return (int) get_transient($this->rateLimitKey($bucket));
    }

    private function rateLimitKey(string $bucket): string
    {
        return 'sja_rl_' . $bucket . '_' . md5(strtolower($this->getClientIp()));
    }

    private function getClientIp(): string
    {
        // No __() — this runs on the determine_current_user path.
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        return is_string($ip) && $ip !== '' ? $ip : 'Unknown';
    }
}
