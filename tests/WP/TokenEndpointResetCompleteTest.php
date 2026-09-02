<?php
/**
 * POST /token/resetpassword/complete — OTP + legacy key paths.
 *
 * Regression anchors:
 *  - key consumption is atomic (compare-and-clear) — two concurrent requests
 *    cannot both pass check_password_reset_key
 *  - successful reset revokes every session token for the user
 *  - `jwt_auth_send_reset_confirmation_email` is opt-out honored
 *
 * Task 3.4 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\WP;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;
use SimpleJwtAuth\PasswordResetCode;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

final class TokenEndpointResetCompleteTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';
    private const NEW_PASS = 'new-pass-123';

    private TokenService $tokenService;
    private TokenEndpoint $endpoint;

    protected function setUp(): void
    {
        require_once __DIR__ . '/shim-functions.php';

        \SjwtTestState::reset();
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        $GLOBALS['__sjwt_options_store']['blogname']         = 'Test Site';
        Config::flushCache();

        $this->tokenService = new TokenService();
        $this->endpoint     = new TokenEndpoint($this->tokenService);
        $this->user();
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

    private function callComplete(array $params): WP_REST_Response
    {
        return $this->endpoint->completeResetPassword(new WP_REST_Request($params));
    }

    private function resetCompleteBucket(): string
    {
        return 'sja_rl_reset_complete_' . md5(strtolower((string) ($_SERVER['REMOTE_ADDR'] ?? '')));
    }

    public function testMissingLoginOrCodeReturns400(): void
    {
        $noLogin   = $this->callComplete(['code' => '123456', 'new_password' => self::NEW_PASS]);
        $noCodeKey = $this->callComplete(['login' => 'jane', 'new_password' => self::NEW_PASS]);

        foreach ([$noLogin, $noCodeKey] as $response) {
            self::assertSame(400, $response->get_status());
            self::assertSame('jwt_auth_invalid_code', $response->get_data()['code']);
            self::assertSame('Reset code or login not specified.', $response->get_data()['message']);
        }
    }

    public function testShortPasswordReturns400(): void
    {
        $code = PasswordResetCode::issue($this->user());

        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => 'short']);

        self::assertSame(400, $response->get_status());
        self::assertSame('jwt_auth_password_too_short', $response->get_data()['code']);
        self::assertSame('Password must be at least 8 characters long.', $response->get_data()['message']);
    }

    public function testMinLengthFilterRespected(): void
    {
        add_filter('jwt_auth_reset_password_min_length', static function (): int {
            return 12;
        });

        $code = PasswordResetCode::issue($this->user());
        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => 'ten-chars-']);

        self::assertSame(400, $response->get_status());
        self::assertSame('jwt_auth_password_too_short', $response->get_data()['code']);
        self::assertSame('Password must be at least 12 characters long.', $response->get_data()['message']);
    }

    public function testOtpHappyPathChangesPasswordAndCleansUp(): void
    {
        // Two live sessions must die with the reset.
        update_user_meta(42, 'jwt_data', [
            'u1' => ['uuid' => 'u1', 'created' => time()],
            'u2' => ['uuid' => 'u2', 'created' => time()],
        ]);

        $code = PasswordResetCode::issue($this->user());
        get_password_reset_key($this->user());

        $passwordResetFired = [];
        add_action('password_reset', static function (WP_User $firedUser, string $firedPass) use (&$passwordResetFired): void {
            $passwordResetFired = [$firedUser->ID, $firedPass];
        }, 10, 2);

        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset_complete', $response->get_data()['code']);
        self::assertSame(200, $response->get_data()['data']['status']);

        // Password actually landed (defends against broken hash overrides).
        $fresh = get_userdata(42);
        self::assertTrue(wp_check_password(self::NEW_PASS, $fresh->user_pass, 42));

        // OTP consumed, deep-link key burned, sessions revoked.
        self::assertSame('', get_user_meta(42, PasswordResetCode::META_KEY, true));
        self::assertSame('', $fresh->user_activation_key);
        self::assertSame('', get_user_meta(42, 'jwt_data', true), 'all sessions revoked with the reset');

        // Core signal + confirmation email (opt-in).
        self::assertSame([42, self::NEW_PASS], $passwordResetFired);
        $mail = $GLOBALS['__sjwt_sent_mail'] ?? [];
        self::assertCount(1, $mail);
        self::assertSame('[Test Site] Your password has been changed', $mail[0]['subject']);

        // Every allowed attempt (even successes) bumps the reset-complete bucket.
        self::assertSame(1, (int) get_transient($this->resetCompleteBucket()));
    }

    public function testWrongCodeReturns400AndBumpsAttempts(): void
    {
        $code = PasswordResetCode::issue($this->user());

        $response = $this->callComplete(['code' => '000000', 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(400, $response->get_status());
        self::assertSame('jwt_auth_invalid_code', $response->get_data()['code']);

        $payload = get_user_meta(42, PasswordResetCode::META_KEY, true);
        self::assertSame(1, (int) ($payload['attempts'] ?? 0));
        self::assertFalse(wp_check_password(self::NEW_PASS, get_userdata(42)->user_pass, 42));
    }

    public function testBurnOutReturns429WithRetryAfterAndClearsCode(): void
    {
        add_filter('jwt_auth_reset_code_max_attempts', static function (): int {
            return 1;
        });

        $code = PasswordResetCode::issue($this->user());

        $response = $this->callComplete(['code' => '999999', 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(429, $response->get_status());
        self::assertSame('jwt_auth_too_many_attempts', $response->get_data()['code']);
        self::assertSame('900', $response->get_headers()['Retry-After'] ?? '');
        self::assertSame('', get_user_meta(42, PasswordResetCode::META_KEY, true), 'burned code cleared');
    }

    public function testBlockedResetCompleteReturns429WithoutConsuming(): void
    {
        [$maxAttempts, $window] = $this->tokenService->getResetCompleteRateLimit();
        $GLOBALS['__sjwt_transients'][$this->resetCompleteBucket()] = ['e' => 0, 'v' => $maxAttempts];

        $code = PasswordResetCode::issue($this->user());
        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(429, $response->get_status());
        self::assertSame((string) $window, $response->get_headers()['Retry-After'] ?? '');
        self::assertSame($maxAttempts, (int) get_transient($this->resetCompleteBucket()));
        self::assertNotSame('', get_user_meta(42, PasswordResetCode::META_KEY, true), 'code not consumed while blocked');
    }

    public function testExpiredKeyReturns400(): void
    {
        $key = get_password_reset_key($this->user());
        $GLOBALS['__sjwt_reset_keys']['jane']['created'] = time() - 90000;

        $response = $this->callComplete(['key' => $key, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(400, $response->get_status());
        self::assertSame('jwt_auth_invalid_key', $response->get_data()['code']);
    }

    public function testKeyHappyPathChangesPassword(): void
    {
        $key = get_password_reset_key($this->user());

        $response = $this->callComplete(['key' => $key, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset_complete', $response->get_data()['code']);
        self::assertTrue(wp_check_password(self::NEW_PASS, get_userdata(42)->user_pass, 42));
        self::assertSame('', get_userdata(42)->user_activation_key, 'key consumed atomically');
    }

    public function testReusedKeyFailsCompareAndClear(): void
    {
        $key = get_password_reset_key($this->user());

        $first  = $this->callComplete(['key' => $key, 'login' => 'jane', 'new_password' => self::NEW_PASS]);
        $second = $this->callComplete(['key' => $key, 'login' => 'jane', 'new_password' => 'other-pass-99']);

        self::assertSame(200, $first->get_status());
        self::assertSame(400, $second->get_status());
        self::assertSame('jwt_auth_invalid_key', $second->get_data()['code']);
        // Second attempt never got to touch the password.
        self::assertTrue(wp_check_password(self::NEW_PASS, get_userdata(42)->user_pass, 42));
    }

    public function testAccountBase64ParamAccepted(): void
    {
        $code = PasswordResetCode::issue($this->user());

        $response = $this->callComplete([
            'code'         => $code,
            'account'      => base64_encode('jane'),
            'new_password' => self::NEW_PASS,
        ]);

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset_complete', $response->get_data()['code']);
    }

    public function testRetrievePasswordUserFilterCanBlock(): void
    {
        $code = PasswordResetCode::issue($this->user());
        add_filter('retrieve_password_user', static function (): WP_Error {
            return new WP_Error('denied', 'Not allowed.');
        });

        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(403, $response->get_status());
        self::assertSame('jwt_auth_reset_password_not_allowed', $response->get_data()['code']);
        self::assertSame('Not allowed.', $response->get_data()['message']);
    }

    public function testConfirmationEmailOptOutHonored(): void
    {
        $code = PasswordResetCode::issue($this->user());
        add_filter('jwt_auth_send_reset_confirmation_email', static function (): bool {
            return false;
        });

        $response = $this->callComplete(['code' => $code, 'login' => 'jane', 'new_password' => self::NEW_PASS]);

        self::assertSame(200, $response->get_status());
        self::assertCount(0, $GLOBALS['__sjwt_sent_mail'] ?? []);
    }
}
