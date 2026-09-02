<?php
/**
 * PasswordResetCode behavior: OTP issue, verify (correct/wrong/expired/burned),
 * clear. Uses the lite stubs (user meta store, filters, wp_salt).
 *
 * Task 1.2 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\PasswordResetCode;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\PasswordResetCode;
use WP_Error;
use WP_User;

final class PasswordResetCodeTest extends TestCase
{
    private WP_User $user;

    protected function setUp(): void
    {
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
        $this->user = new WP_User([
            'ID'          => 42,
            'user_email'  => 'jane@example.test',
            'user_login'  => 'jane',
            'display_name' => 'Jane',
        ]);
    }

    private function storedPayload(): mixed
    {
        return get_user_meta($this->user->ID, PasswordResetCode::META_KEY, true);
    }

    public function testIssueGeneratesSixDigitCodeAndStoresPayload(): void
    {
        $code = PasswordResetCode::issue($this->user);

        self::assertMatchesRegularExpression('/^\d{6}$/', $code);

        $payload = $this->storedPayload();
        self::assertIsArray($payload);
        self::assertArrayHasKey('hash', $payload);
        self::assertArrayHasKey('expires', $payload);
        self::assertSame(0, $payload['attempts']);
        self::assertGreaterThan(time(), $payload['expires']);
        self::assertLessThanOrEqual(30 * MINUTE_IN_SECONDS + 5, $payload['expires'] - time());
    }

    public function testIssueHonorsLengthFilterWithClamping(): void
    {
        add_filter('jwt_auth_reset_code_length', static fn() => 4);
        $code = PasswordResetCode::issue($this->user);
        self::assertMatchesRegularExpression('/^\d{4}$/', $code);

        add_filter('jwt_auth_reset_code_length', static fn() => 2);
        $code = PasswordResetCode::issue($this->user);
        self::assertMatchesRegularExpression('/^\d{4}$/', $code, 'length clamped up to 4');

        add_filter('jwt_auth_reset_code_length', static fn() => 12);
        $code = PasswordResetCode::issue($this->user);
        self::assertMatchesRegularExpression('/^\d{8}$/', $code, 'length clamped down to 8');
    }

    public function testIssueHonorsTtlFilterWithClamping(): void
    {
        add_filter('jwt_auth_reset_code_ttl', static fn() => 120);
        $code = PasswordResetCode::issue($this->user);
        $ttl  = $this->storedPayload()['expires'] - time();
        self::assertGreaterThanOrEqual(115, $ttl);
        self::assertLessThanOrEqual(125, $ttl);

        add_filter('jwt_auth_reset_code_ttl', static fn() => 10);
        $code = PasswordResetCode::issue($this->user);
        $ttl  = $this->storedPayload()['expires'] - time();
        self::assertGreaterThanOrEqual(55, $ttl, 'ttl clamped up to 60');
    }

    public function testVerifyCorrectCodeReturnsTrue(): void
    {
        $code = PasswordResetCode::issue($this->user);
        self::assertTrue(PasswordResetCode::verify($this->user, $code));
    }

    public function testVerifyMissingRecordIsInvalid(): void
    {
        $result = PasswordResetCode::verify($this->user, '123456');

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_invalid_code', $result->get_error_code());
        self::assertSame(['status' => 400], $result->get_error_data());
    }

    public function testVerifyWrongCodeIncrementsAttemptCounter(): void
    {
        $code = PasswordResetCode::issue($this->user);
        $wrong = ($code === '000000') ? '000001' : '000000';

        $result = PasswordResetCode::verify($this->user, $wrong);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_invalid_code', $result->get_error_code());
        self::assertSame(1, $this->storedPayload()['attempts']);
    }

    public function testVerifyBurnsCodeAfterMaxAttempts(): void
    {
        add_filter('jwt_auth_reset_code_max_attempts', static fn() => 2);
        $code = PasswordResetCode::issue($this->user);
        $wrong = ($code === '000000') ? '000001' : '000000';

        // First wrong guess: still a plain invalid-code error, attempt bumped.
        $result = PasswordResetCode::verify($this->user, $wrong);
        self::assertSame('jwt_auth_invalid_code', $result->get_error_code());

        // Second wrong guess burns the code: too-many-attempts + cleared meta.
        $result = PasswordResetCode::verify($this->user, $wrong);
        self::assertSame('jwt_auth_too_many_attempts', $result->get_error_code());
        self::assertSame(['status' => 429], $result->get_error_data());
        self::assertSame('', $this->storedPayload(), 'meta cleared after burn-out');

        // After the burn, the record is gone → back to plain invalid-code.
        $result = PasswordResetCode::verify($this->user, $wrong);
        self::assertSame('jwt_auth_invalid_code', $result->get_error_code());
    }

    public function testVerifyExpiredCodeClearsAndRejects(): void
    {
        $code = PasswordResetCode::issue($this->user);

        $payload = $this->storedPayload();
        $payload['expires'] = time() - 10;
        update_user_meta($this->user->ID, PasswordResetCode::META_KEY, $payload);

        $result = PasswordResetCode::verify($this->user, $code);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('jwt_auth_invalid_code', $result->get_error_code());
        self::assertSame('', $this->storedPayload(), 'expired code cleared');
    }

    public function testVerifyRejectsNonNumericAndEmptyCodes(): void
    {
        PasswordResetCode::issue($this->user);

        foreach (['abc', '', '12a3', '12 34a'] as $bad) {
            $result = PasswordResetCode::verify($this->user, $bad);
            self::assertInstanceOf(WP_Error::class, $result, "code " . var_export($bad, true));
            self::assertSame('jwt_auth_invalid_code', $result->get_error_code());
        }
    }

    public function testVerifyStripsWhitespaceBeforeComparing(): void
    {
        $code = PasswordResetCode::issue($this->user);
        $spaced = implode(' ', str_split($code, 2));

        self::assertTrue(PasswordResetCode::verify($this->user, $spaced));
    }

    public function testIssueReplacesPreviousCode(): void
    {
        $first = PasswordResetCode::issue($this->user);
        $second = PasswordResetCode::issue($this->user);

        $result = PasswordResetCode::verify($this->user, $first);
        self::assertInstanceOf(WP_Error::class, $result, 'first code invalid after re-issue');

        self::assertTrue(PasswordResetCode::verify($this->user, $second));
    }

    public function testClearRemovesStoredMeta(): void
    {
        PasswordResetCode::issue($this->user);
        self::assertNotSame('', $this->storedPayload());

        PasswordResetCode::clear($this->user);
        self::assertSame('', $this->storedPayload());
    }
}
