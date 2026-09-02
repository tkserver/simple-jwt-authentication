<?php
/**
 * POST /token (login) — endpoint behavior through the WP shim.
 *
 * Regression anchor: the login response `user_id` must be a *string* —
 * an int crashed React Native AsyncStorage (v1 shape parity).
 *
 * Task 3.1 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\WP;

use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;
use WP_REST_Request;
use WP_REST_Response;

final class TokenEndpointLoginTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';

    private TokenService $tokenService;
    private TokenEndpoint $endpoint;

    protected function setUp(): void
    {
        require_once __DIR__ . '/shim-functions.php';

        \SjwtTestState::reset();
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        Config::flushCache();

        $this->tokenService = new TokenService();
        $this->endpoint     = new TokenEndpoint($this->tokenService);

        sjwtAddUser([
            'ID'           => 42,
            'user_login'   => 'jane',
            'user_email'   => 'jane@example.test',
            'user_nicename' => 'jane',
            'display_name' => 'Jane',
            'user_pass'    => wp_hash_password('secret-pass'),
        ]);
    }

    private function callLogin(array $params): WP_REST_Response
    {
        return $this->endpoint->generateToken(new WP_REST_Request($params));
    }

    private function loginBucketKey(): string
    {
        return 'sja_rl_login_' . md5(strtolower((string) ($_SERVER['REMOTE_ADDR'] ?? '')));
    }

    public function testHappyPathReturnsTokenAndV1Shape(): void
    {
        $response = $this->callLogin(['username' => 'jane', 'password' => 'secret-pass']);

        self::assertSame(200, $response->get_status());
        $data = $response->get_data();

        self::assertSame('42', $data['user_id'], 'regression: user_id must be a string');
        self::assertNotSame('', $data['token']);
        self::assertSame('jane@example.test', $data['user_email']);
        self::assertSame('jane', $data['user_nicename']);
        self::assertSame('Jane', $data['user_display_name']);
        self::assertIsInt($data['token_expires']);
        self::assertGreaterThan(0, $data['token_expires']);
    }

    public function testTokenDecodesToSub42(): void
    {
        $data = $this->callLogin(['username' => 'jane', 'password' => 'secret-pass'])->get_data();

        $decoded = (array) \Firebase\JWT\JWT::decode($data['token'], new Key(self::SECRET, 'HS256'));

        self::assertSame(42, $decoded['data']->user->id);
        self::assertArrayHasKey('uuid', $decoded);
        self::assertSame('https://example.test', $decoded['iss']);
    }

    public function testWrongPasswordReturns401WithWpErrorCode(): void
    {
        $response = $this->callLogin(['username' => 'jane', 'password' => 'wrong']);

        self::assertSame(401, $response->get_status());
        $data = $response->get_data();

        self::assertSame('[jwt_auth] incorrect_password', $data['code']);
        self::assertNotSame('', $data['message']);
    }

    public function testUnknownUserReturns401WithWpErrorCode(): void
    {
        $response = $this->callLogin(['username' => 'who-is-this', 'password' => 'whatever']);

        self::assertSame(401, $response->get_status());
        self::assertSame('[jwt_auth] invalid_username', $response->get_data()['code']);
    }

    public function testMissingSecretReturns503(): void
    {
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = [];
        Config::flushCache();

        $response = $this->callLogin(['username' => 'jane', 'password' => 'secret-pass']);

        self::assertSame(503, $response->get_status());
        self::assertSame('jwt_auth_bad_config', $response->get_data()['code']);
    }

    public function testRateLimitExceededReturns429WithRetryAfter(): void
    {
        $bucket = $this->loginBucketKey();
        [$maxAttempts, $window] = $this->tokenService->getLoginRateLimit();

        // Over the budget: next login attempt must be refused outright.
        // Transient rows are ['e' => expiry, 'v' => value]; e=0 = never expires.
        $GLOBALS['__sjwt_transients'][$bucket] = ['e' => 0, 'v' => $maxAttempts + 1];

        $response = $this->callLogin(['username' => 'jane', 'password' => 'secret-pass']);

        self::assertSame(429, $response->get_status());
        $data = $response->get_data();
        self::assertSame('jwt_auth_too_many_attempts', $data['code']);
        self::assertSame((string) $window, $response->get_headers()['Retry-After'] ?? '');
    }

    public function testSuccessResetsFailureCounter(): void
    {
        $bucket = $this->loginBucketKey();

        $this->callLogin(['username' => 'jane', 'password' => 'wrong']);
        $this->callLogin(['username' => 'jane', 'password' => 'wrong']);
        self::assertSame(2, (int) get_transient($bucket), 'two failures counted');

        $this->callLogin(['username' => 'jane', 'password' => 'secret-pass']);

        self::assertFalse(get_transient($bucket), 'success clears the counter');
    }

    public function testBlockedBucketIsNotResetByAttempt(): void
    {
        $bucket = $this->loginBucketKey();
        $GLOBALS['__sjwt_transients'][$bucket] = ['e' => 0, 'v' => 999];

        $this->callLogin(['username' => 'jane', 'password' => 'secret-pass']);

        self::assertSame(999, (int) get_transient($bucket), 'blocked requests never reset the bucket');
    }
}
