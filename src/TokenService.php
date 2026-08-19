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

    private ?WP_Error $jwtError = null;

    /**
     * Generate a signed JWT for the given user.
     *
     * @return array{token: string, user_id: int, user_email: string, user_nicename: string, user_display_name: string, token_expires: int}
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

        $payload = [
            'uuid'  => $uuid,
            'iss'   => get_bloginfo('url'),
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

        return apply_filters('jwt_auth_token_before_dispatch', [
            'token'             => $token,
            'user_id'           => $user->ID,
            'user_email'        => $user->user_email,
            'user_nicename'     => $user->user_nicename,
            'user_display_name' => $user->display_name,
            'token_expires'     => $expire,
        ], $user);
    }

    /**
     * Validate the Bearer token from the current request.
     *
     * @return \stdClass|WP_Error The decoded token payload, or a WP_Error.
     */
    public function validateToken(bool $forMiddleware = false): \stdClass|WP_Error
    {
        $authHeader = $this->getAuthHeader();
        if ($authHeader === null) {
            return new WP_Error(
                'jwt_auth_no_auth_header',
                __('Authorization header not found.', 'simple-jwt-authentication'),
                ['status' => 401]
            );
        }

        if (!preg_match('/^Bearer\s+(\S+)$/', $authHeader, $matches)) {
            return new WP_Error(
                'jwt_auth_bad_auth_header',
                __('Authorization header malformed.', 'simple-jwt-authentication'),
                ['status' => 401]
            );
        }

        $secretKey = Config::getSecretKey();
        if ($secretKey === null) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configured properly. The key is missing.', 'simple-jwt-authentication'),
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

        if (!property_exists($token, 'iss') || get_bloginfo('url') !== $token->iss) {
            return new WP_Error(
                'jwt_auth_bad_iss',
                __('The issuer does not match this server.', 'simple-jwt-authentication'),
                ['status' => 403]
            );
        }

        if (!isset($token->data->user->id)) {
            return new WP_Error(
                'jwt_auth_bad_request',
                __('User ID not found in the token.', 'simple-jwt-authentication'),
                ['status' => 403]
            );
        }

        $userId    = (int) $token->data->user->id;
        $tokenUuid = (string) $token->uuid;

        if (!$this->verifyTokenUuid($userId, $tokenUuid, $forMiddleware)) {
            return new WP_Error(
                'jwt_auth_token_revoked',
                __('Token has been revoked.', 'simple-jwt-authentication'),
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

        $now      = time();
        $removed  = 0;
        $filtered = [];

        foreach ($tokens as $tokenData) {
            if (($tokenData['expires'] ?? 0) < $now) {
                $removed++;
            } else {
                $filtered[] = $tokenData;
            }
        }

        if ($removed > 0) {
            update_user_meta($userId, 'jwt_data', $filtered);
        }

        return $removed;
    }

    private function getAuthHeader(): ?string
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? null;

        if ($auth === null) {
            $auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
        }

        return $auth !== null ? $auth : null;
    }

    private function storeTokenMetadata(int $userId, string $uuid, int $issuedAt, int $expires): void
    {
        $jwtData = get_user_meta($userId, 'jwt_data', true);
        if (!is_array($jwtData)) {
            $jwtData = [];
        }

        $jwtData[] = [
            'uuid'      => $uuid,
            'issued_at' => $issuedAt,
            'expires'   => $expires,
            'ip'        => $this->getClientIp(),
            'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'last_used' => time(),
        ];

        update_user_meta($userId, 'jwt_data', apply_filters('simple_jwt_auth_save_user_data', $jwtData));
    }

    private function verifyTokenUuid(int $userId, string $tokenUuid, bool $updateLastUsed): bool
    {
        $tokens = get_user_meta($userId, 'jwt_data', true);
        if (!is_array($tokens)) {
            return false;
        }

        foreach ($tokens as $key => $tokenData) {
            if (hash_equals($tokenData['uuid'], $tokenUuid)) {
                if ($updateLastUsed) {
                    $tokens[$key]['last_used'] = time();
                    $tokens[$key]['ip']        = $this->getClientIp();
                    $tokens[$key]['ua']        = $_SERVER['HTTP_USER_AGENT'] ?? '';
                    update_user_meta($userId, 'jwt_data', $tokens);
                }
                return true;
            }
        }

        return false;
    }

    private function getClientIp(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? __('Unknown', 'simple-jwt-authentication');
    }
}
