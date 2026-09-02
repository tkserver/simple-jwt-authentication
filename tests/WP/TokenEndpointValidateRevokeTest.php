<?php
/**
 * POST /token/validate + POST /token/revoke (endpoint level).
 *
 * Task 3.2 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\WP;

use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

final class TokenEndpointValidateRevokeTest extends TestCase
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
    }

    private function user(): WP_User
    {
        return sjwtAddUser([
            'ID'          => 42,
            'user_login'  => 'jane',
            'user_email'  => 'jane@example.test',
            'user_nicename' => 'jane',
            'display_name' => 'Jane',
            'user_pass'    => wp_hash_password('secret-pass'),
        ]);
    }

    private function withValidToken(): string
    {
        $token = $this->tokenService->generateToken($this->user())['token'];
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        return $token;
    }

    private function callValidate(): WP_REST_Response
    {
        return $this->endpoint->validateToken(new WP_REST_Request([]));
    }

    private function callRevoke(): WP_REST_Response
    {
        return $this->endpoint->revokeToken(new WP_REST_Request([]));
    }

    public function testValidTokenReturns200(): void
    {
        $this->withValidToken();

        $response = $this->callValidate();

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_valid_token', $response->get_data()['code']);
        self::assertSame(200, $response->get_data()['data']['status']);
    }

    public function testMissingHeaderReturns401(): void
    {
        $response = $this->callValidate();

        self::assertSame(401, $response->get_status());
        self::assertSame('jwt_auth_no_auth_header', $response->get_data()['code']);
    }

    public function testExpiredTokenReturns401(): void
    {
        $this->withValidToken();

        // Mint an otherwise-valid token whose exp has already passed. The exp
        // check runs during decode (before revocation lookup), so any uuid
        // value is fine here.
        $forged = \Firebase\JWT\JWT::encode([
            'uuid' => '00000000-0000-4000-8000-000000000042',
            'iss'  => 'https://example.test',
            'iat'  => time() - 100,
            'nbf'  => time() - 100,
            'exp'  => time() - 50,
            'data' => ['user' => ['id' => 42]],
        ], self::SECRET, 'HS256');
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $forged;

        $response = $this->callValidate();

        self::assertSame(401, $response->get_status());
        self::assertSame('jwt_auth_expired_token', $response->get_data()['code']);
    }

    public function testGarbageTokenReturns401(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer this-is-not-a-jwt';

        $response = $this->callValidate();

        self::assertSame(401, $response->get_status());
        self::assertSame('jwt_auth_invalid_token', $response->get_data()['code']);
    }

    public function testRevokedTokenReturns403WithTranslatedMessage(): void
    {
        $this->withValidToken();
        $this->tokenService->revokeCurrentToken();

        $response = $this->callValidate();

        self::assertSame(403, $response->get_status());
        self::assertSame('jwt_auth_token_revoked', $response->get_data()['code']);
        self::assertSame('Token has been revoked.', $response->get_data()['message']);
    }

    public function testRevokeClearsSessionMetaAndSubsequentValidateFails(): void
    {
        $this->withValidToken();

        $response = $this->callRevoke();
        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_revoked_token', $response->get_data()['code']);

        $rows = get_user_meta(42, 'jwt_data', true);
        self::assertTrue(is_array($rows) || $rows === '');
        self::assertEmpty($rows, 'session entry removed from user meta');

        $validateAgain = $this->callValidate();
        self::assertSame(403, $validateAgain->get_status());
        self::assertSame('jwt_auth_token_revoked', $validateAgain->get_data()['code']);
    }

    public function testRevokeWithoutTokenMapsToOuter403WithInner401(): void
    {
        $response = $this->callRevoke();

        // Endpoint maps everything except revoked (200) / no-token-to-revoke
        // (404) to an outer 403; the inner payload keeps the source status.
        self::assertSame(403, $response->get_status());
        self::assertSame('jwt_auth_no_auth_header', $response->get_data()['code']);
        self::assertSame(401, $response->get_data()['data']['status']);
    }

    public function testRevokeTwiceReturns403OnSecondAttempt(): void
    {
        $this->withValidToken();

        $first  = $this->callRevoke();
        $second = $this->callRevoke();

        self::assertSame(200, $first->get_status());
        self::assertSame(403, $second->get_status());
        self::assertSame('jwt_auth_token_revoked', $second->get_data()['code']);
        self::assertSame(403, $second->get_data()['data']['status']);
    }

    public function testValidateWithoutSecretReturns503(): void
    {
        // Header is checked first, so it must be present (but secret missing)
        // for this test to reach the config branch.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer whatever';
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = [];
        Config::flushCache();

        $response = $this->callValidate();

        self::assertSame(503, $response->get_status());
        self::assertSame('jwt_auth_bad_config', $response->get_data()['code']);
    }

    public function testValidatedTokenIsWpErrorFreeOnSuccess(): void
    {
        $this->withValidToken();

        $this->callValidate();

        self::assertNull($this->tokenService->getJwtError());
    }

    public function testEndpointValidateDoesNotStoreJwtError(): void
    {
        // JWT error storage is a middleware handoff (RestController) — the
        // endpoint's own validate call leaves no stored error behind.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer this-is-not-a-jwt';

        $this->callValidate();

        self::assertNull($this->tokenService->getJwtError());
    }
}
