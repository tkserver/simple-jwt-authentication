<?php
/**
 * TokenService JWT round-trip: sign → verify, expiry, tampering, issuer pin,
 * not-before, revocation-free uuid checks.
 *
 * Task 1.3 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\TokenService;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_User;

final class TokenServiceRoundTripTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';

    private TokenService $service;
    private WP_User $user;

    protected function setUp(): void
    {
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
        $this->configureSecret();
        $this->service = new TokenService();
        $this->user    = new WP_User([
            'ID'          => 42,
            'user_email'  => 'jane@example.test',
            'user_login'  => 'jane',
            'user_nicename' => 'jane',
            'display_name' => 'Jane',
        ]);
    }

    private function configureSecret(): void
    {
        $GLOBALS['__sjwt_options_store'][\SimpleJwtAuth\Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        \SimpleJwtAuth\Config::flushCache();
    }

    private function setAuthHeader(string $token): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
    }

    private function generate(): string
    {
        return $this->service->generateToken($this->user)['token'];
    }

    public function testGenerateTokenReturnsV1CompatibleJsonShape(): void
    {
        $result = $this->service->generateToken($this->user);

        self::assertMatchesRegularExpression('/^[\w\-]+\.[\w\-]+\.[\w\-]+$/', $result['token']);
        self::assertSame('42', $result['user_id'], 'user_id MUST be a string (v1 shape)');
        self::assertSame('jane@example.test', $result['user_email']);
        self::assertSame('jane', $result['user_nicename']);
        self::assertSame('Jane', $result['user_display_name']);
        self::assertIsInt($result['token_expires']);
        self::assertGreaterThan(time(), $result['token_expires']);
    }

    public function testGenerateTokenStoresJwtDataEntry(): void
    {
        $result = $this->service->generateToken($this->user);

        $rows = get_user_meta(42, 'jwt_data', true);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);

        $row = $rows[0];
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $row['uuid'],
            'stored session uuid must be a uuid4'
        );
        self::assertSame('198.51.100.7', $row['ip']);
        self::assertSame('phpunit-test-agent', $row['ua']);
        self::assertIsInt($row['issued_at']);
        self::assertIsInt($row['expires']);
        self::assertIsInt($row['last_used']);
    }

    public function testGenerateTokenThrowsWithoutSecretKey(): void
    {
        $GLOBALS['__sjwt_options_store'] = [];
        \SimpleJwtAuth\Config::flushCache();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('JWT secret key is not configured.');

        $this->service->generateToken($this->user);
    }

    public function testValidateTokenHappyPath(): void
    {
        $token = $this->generate();
        $this->setAuthHeader($token);

        $payload = $this->service->validateToken();

        self::assertNotInstanceOf(WP_Error::class, $payload);
        self::assertSame('https://example.test', $payload->iss);
        self::assertSame(42, $payload->data->user->id);
        self::assertSame('https://example.test', $payload->iss);

        // uuid must match the stored session entry.
        $row = get_user_meta(42, 'jwt_data', true)[0];
        self::assertSame($row['uuid'], $payload->uuid);
    }

    public function testValidateTokenNoHeader(): void
    {
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_no_auth_header', $result->get_error_code());
        self::assertSame(['status' => 401], $result->get_error_data());
    }

    public function testValidateTokenMalformedHeader(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=';
        $result = $this->service->validateToken();
        self::assertSame('jwt_auth_bad_auth_header', $result->get_error_code());

        // Token segment may not contain whitespace.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer two segments';
        $result = $this->service->validateToken();
        self::assertSame('jwt_auth_bad_auth_header', $result->get_error_code());
        self::assertSame(['status' => 401], $result->get_error_data());
    }

    public function testValidateTokenMissingSecretConfig(): void
    {
        $GLOBALS['__sjwt_options_store'] = [];
        \SimpleJwtAuth\Config::flushCache();

        $this->setAuthHeader('not.a.token');
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_bad_config', $result->get_error_code());
        self::assertSame(['status' => 503], $result->get_error_data());
    }

    public function testValidateTokenRejectsExpiredToken(): void
    {
        add_filter('jwt_auth_expire', static fn($defaultExp, $issuedAt) => $issuedAt - 10, 10, 2);
        $token = $this->generate();
        $this->setAuthHeader($token);

        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_expired_token', $result->get_error_code());
        self::assertSame(['status' => 401], $result->get_error_data());
    }

    public function testValidateTokenRejectsNotYetValidToken(): void
    {
        add_filter('jwt_auth_not_before', static fn($defaultIat) => time() + 600);
        $token = $this->generate();
        $this->setAuthHeader($token);

        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_not_yet_valid', $result->get_error_code());
    }

    public function testValidateTokenRejectsTamperedSignature(): void
    {
        $token = $this->generate();

        // Same payload, signed with a different secret → signature failure.
        $payload = JWT::decode($token, new Key(self::SECRET, 'HS256'));
        $forged  = JWT::encode((array) $payload, 'an-entirely-different-secret-0123456789', 'HS256');

        $this->setAuthHeader($forged);
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_invalid_token', $result->get_error_code());
        self::assertSame(['status' => 401], $result->get_error_data());
    }

    public function testValidateTokenRejectsIssuerMismatch(): void
    {
        // Token signed under a pinned issuer, validated with the default one.
        add_filter('jwt_auth_token_iss', static fn() => 'https://other.example');
        $token = $this->generate();
        $GLOBALS['__sjwt_filters'] = []; // drop the issuer pin before validating

        $this->setAuthHeader($token);
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_bad_iss', $result->get_error_code());
        self::assertSame(['status' => 403], $result->get_error_data());
    }

    public function testValidateTokenRejectsGarbageTokenString(): void
    {
        $this->setAuthHeader('this-is-not-a-real-token.at.all');
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_invalid_token', $result->get_error_code());
    }

    public function testValidateTokenRejectsPayloadWithoutUserId(): void
    {
        $token = $this->generate();

        $payload = JWT::decode($token, new Key(self::SECRET, 'HS256'));
        unset($payload->data);
        $stripped = JWT::encode((array) $payload, self::SECRET, 'HS256');

        $this->setAuthHeader($stripped);
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_bad_request', $result->get_error_code());
        self::assertSame(['status' => 403], $result->get_error_data());
    }

    public function testValidateTokenRejectsRevokedUuid(): void
    {
        $token = $this->generate();
        delete_user_meta(42, 'jwt_data');

        $this->setAuthHeader($token);
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_token_revoked', $result->get_error_code());
        self::assertSame(['status' => 403], $result->get_error_data());
    }

    public function testValidateTokenRejectsUnknownUuid(): void
    {
        $token = $this->generate();

        update_user_meta(42, 'jwt_data', [
            [
                'uuid'      => 'some-other-uuid',
                'issued_at' => time(),
                'expires'   => time() + 3600,
                'ip'        => '198.51.100.7',
                'ua'        => 'phpunit-test-agent',
                'last_used' => time(),
            ],
        ]);

        $this->setAuthHeader($token);
        $result = $this->service->validateToken();

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_token_revoked', $result->get_error_code());
    }

    public function testIssuerFilterPinsIssuerOnSignAndVerify(): void
    {
        add_filter('jwt_auth_token_iss', static fn() => 'https://pinned.example');
        $token = $this->generate();

        $this->setAuthHeader($token);
        $payload = $this->service->validateToken();

        self::assertNotInstanceOf(WP_Error::class, $payload);
        self::assertSame('https://pinned.example', $payload->iss);
    }
}
