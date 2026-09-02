<?php
/**
 * TokenService revocation + session bookkeeping: revoke current token,
 * expired-entry pruning, per-user session soft-cap, last_used throttling,
 * revoke-all.
 *
 * Task 1.4 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\TokenService;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_User;

final class TokenServiceRevocationTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';

    private TokenService $service;
    private WP_User $user;

    protected function setUp(): void
    {
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
        $GLOBALS['__sjwt_options_store'][\SimpleJwtAuth\Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        \SimpleJwtAuth\Config::flushCache();

        $this->service = new TokenService();
        $this->user    = new WP_User([
            'ID'          => 42,
            'user_email'  => 'jane@example.test',
            'user_login'  => 'jane',
            'display_name' => 'Jane',
        ]);
    }

    private function setAuthHeader(string $token): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
    }

    private function row(string $uuid, int $issuedAt, int $expires): array
    {
        return [
            'uuid'      => $uuid,
            'issued_at' => $issuedAt,
            'expires'   => $expires,
            'ip'        => '198.51.100.7',
            'ua'        => 'phpunit-test-agent',
            'last_used' => $issuedAt,
        ];
    }

    public function testRevokeCurrentTokenRevokesSession(): void
    {
        $token = $this->service->generateToken($this->user)['token'];
        $this->setAuthHeader($token);

        $result = $this->service->revokeCurrentToken();

        self::assertSame('jwt_auth_revoked_token', $result['code']);
        self::assertSame(['status' => 200], $result['data']);
        self::assertSame(
            [],
            get_user_meta(42, 'jwt_data', true),
            'session entry removed (revocation rewrites meta with zero entries)'
        );

        $result = $this->service->validateToken();
        self::assertSame('jwt_auth_token_revoked', $result->get_error_code());
    }

    public function testRevokeCurrentTokenMapsAuthErrorsWithStatusCode(): void
    {
        // No Authorization header → validateToken error is mapped as-is.
        $result = $this->service->revokeCurrentToken();

        self::assertSame('jwt_auth_no_auth_header', $result['code']);
        self::assertSame(['status' => 401], $result['data']);
    }

    public function testRevokeCurrentTokenWhenSessionAlreadyGone(): void
    {
        $token = $this->service->generateToken($this->user)['token'];
        delete_user_meta(42, 'jwt_data');
        $this->setAuthHeader($token);

        $result = $this->service->revokeCurrentToken();

        // validateToken fails first (uuid not found) → mapped revoked error.
        self::assertSame('jwt_auth_token_revoked', $result['code']);
        self::assertSame(['status' => 403], $result['data']);
    }

    public function testRemoveExpiredTokensPrunesExpiredEntries(): void
    {
        $now = time();
        update_user_meta(42, 'jwt_data', [
            $this->row('expired-1', $now - 300, $now - 100),
            $this->row('keep-1',    $now - 200, $now + 1000),
            $this->row('keep-2',    $now - 100, $now + 999),
        ]);

        $removed = $this->service->removeExpiredTokens(42);

        self::assertSame(1, $removed);
        $rows = get_user_meta(42, 'jwt_data', true);
        self::assertSame(['keep-1', 'keep-2'], array_column($rows, 'uuid'), 'order preserved');
    }

    public function testRemoveExpiredTokensWithNoMetaReturnsZero(): void
    {
        self::assertSame(0, $this->service->removeExpiredTokens(42));
    }

    public function testRemoveExpiredTokensNothingExpiredKeepsMeta(): void
    {
        $now = time();
        $rows = [
            $this->row('keep-1', $now - 200, $now + 1000),
            $this->row('keep-2', $now - 100, $now + 999),
        ];
        update_user_meta(42, 'jwt_data', $rows);

        self::assertSame(0, $this->service->removeExpiredTokens(42));
        self::assertSame($rows, get_user_meta(42, 'jwt_data', true));
    }

    public function testSessionCapKeepsNewestEntries(): void
    {
        add_filter('jwt_auth_max_tokens_per_user', static fn() => 3);

        $now = time();
        update_user_meta(42, 'jwt_data', [
            $this->row('oldest', $now - 300, $now + 3600),
            $this->row('middle', $now - 200, $now + 3600),
            $this->row('newest', $now - 100, $now + 3600),
        ]);

        $token = $this->service->generateToken($this->user)['token'];

        $rows = get_user_meta(42, 'jwt_data', true);
        self::assertCount(3, $rows, 'soft cap enforced');
        $uuids = array_column($rows, 'uuid');
        self::assertNotContains('oldest', $uuids, 'oldest session dropped first');
        self::assertContains('newest', $uuids);
        self::assertContains('middle', $uuids);

        // The freshly issued token must survive the cap and stay valid.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        self::assertNotInstanceOf(WP_Error::class, $this->service->validateToken());
    }

    public function testSessionCapDisabledWhenFilterReturnsZero(): void
    {
        add_filter('jwt_auth_max_tokens_per_user', static fn() => 0);

        $now = time();
        update_user_meta(42, 'jwt_data', [
            $this->row('u1', $now - 300, $now + 3600),
            $this->row('u2', $now - 200, $now + 3600),
            $this->row('u3', $now - 100, $now + 3600),
        ]);

        $this->service->generateToken($this->user);

        self::assertCount(4, get_user_meta(42, 'jwt_data', true), 'cap of 0 = unlimited');
    }

    public function testExpiredEntriesPrunedBeforeAppend(): void
    {
        $now = time();
        update_user_meta(42, 'jwt_data', [
            $this->row('stale-1', $now - 300, $now - 100),
            $this->row('stale-2', $now - 200, $now - 5),
        ]);

        $this->service->generateToken($this->user);

        $rows = get_user_meta(42, 'jwt_data', true);
        self::assertCount(1, $rows, 'expired entries dropped before appending');
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/i', $rows[0]['uuid']);
    }

    public function testLastUsedUpdatedViaMiddlewarePath(): void
    {
        $token = $this->service->generateToken($this->user)['token'];

        // Make the stored row visibly stale + wrong ip/ua to prove the rewrite.
        $rows = get_user_meta(42, 'jwt_data', true);
        $rows[0]['last_used'] = time() - 7200;
        $rows[0]['ip'] = 'old';
        $rows[0]['ua'] = 'old';
        update_user_meta(42, 'jwt_data', $rows);

        $this->setAuthHeader($token);
        $this->service->validateToken(forMiddleware: true);

        $row = get_user_meta(42, 'jwt_data', true)[0];
        self::assertGreaterThanOrEqual(time() - 5, $row['last_used']);
        self::assertSame('198.51.100.7', $row['ip']);
        self::assertSame('phpunit-test-agent', $row['ua']);
    }

    public function testLastUsedNotRewrittenWithinInterval(): void
    {
        $token = $this->service->generateToken($this->user)['token'];

        $rows = get_user_meta(42, 'jwt_data', true);
        $rows[0]['last_used'] = time() - 60;
        update_user_meta(42, 'jwt_data', $rows);
        $before = get_user_meta(42, 'jwt_data', true);

        $this->setAuthHeader($token);
        $this->service->validateToken(forMiddleware: true);

        self::assertSame(
            $before,
            get_user_meta(42, 'jwt_data', true),
            'no user-meta write within the hourly window (write-amplification regression)'
        );
    }

    public function testDefaultValidateTokenNeverTouchesLastUsed(): void
    {
        $token = $this->service->generateToken($this->user)['token'];

        $rows = get_user_meta(42, 'jwt_data', true);
        $rows[0]['last_used'] = time() - 7200;
        update_user_meta(42, 'jwt_data', $rows);
        $before = get_user_meta(42, 'jwt_data', true);

        $this->setAuthHeader($token);
        $this->service->validateToken();

        self::assertSame($before, get_user_meta(42, 'jwt_data', true));
    }

    public function testRevokeAllUserTokensRemovesAllAndCounts(): void
    {
        $now = time();
        update_user_meta(42, 'jwt_data', [
            $this->row('u1', $now - 300, $now + 3600),
            $this->row('u2', $now - 200, $now + 3600),
            $this->row('u3', $now - 100, $now + 3600),
        ]);

        self::assertSame(3, $this->service->revokeAllUserTokens(42));
        self::assertSame('', get_user_meta(42, 'jwt_data', true));
    }

    public function testRevokeAllUserTokensWithNoMetaReturnsZero(): void
    {
        self::assertSame(0, $this->service->revokeAllUserTokens(42));
    }
}
