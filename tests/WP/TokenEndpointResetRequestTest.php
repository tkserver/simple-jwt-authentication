<?php
/**
 * POST /token/resetpassword (request / email path).
 *
 * Regression anchors:
 *  - one generic 200 response for every outcome (no username enumeration) — 2.0.1
 *  - reset URL template placeholders `{key}`/`{login}` replace the wp-login
 *    deep link entirely
 *  - mail failure must drop the OTP (no stuck codes)
 *
 * Task 3.3 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\WP;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;
use SimpleJwtAuth\PasswordResetCode;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;

final class TokenEndpointResetRequestTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';

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

    private function callReset(string $username): WP_REST_Response
    {
        return $this->endpoint->resetPassword(new WP_REST_Request(['username' => $username]));
    }

    private function sentMail(): array
    {
        return $GLOBALS['__sjwt_sent_mail'] ?? [];
    }

    private function otpFromMessage(string $message): string
    {
        if (preg_match('/(?<!\d)\d{6}(?!\d)/', $message, $m)) {
            return $m[0];
        }
        return '';
    }

    public function testKnownUserGetsGeneric200AndEmail(): void
    {
        $response = $this->callReset('jane');

        self::assertSame(200, $response->get_status());
        $data = $response->get_data();

        self::assertSame('jwt_auth_password_reset', $data['code']);
        self::assertSame('If the username or email address exists on this site, a password reset code has been sent.', $data['message']);
        self::assertSame(200, $data['data']['status']);

        $mail = $this->sentMail();
        self::assertCount(1, $mail);
        self::assertSame('jane@example.test', $mail[0]['to']);
        self::assertSame('[Test Site] Password Reset Code', $mail[0]['subject']);
        self::assertSame(['Content-Type: text/plain; charset=UTF-8'], $mail[0]['headers']);
    }

    public function testUnknownUserGetsGeneric200AndNoEmail(): void
    {
        $response = $this->callReset('no-such-user');

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset', $response->get_data()['code']);
        self::assertCount(0, $this->sentMail(), 'no enumeration: identical response, no mail');
    }

    public function testEmptyUsernameGetsGeneric200AndNoEmail(): void
    {
        $response = $this->callReset('');

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset', $response->get_data()['code']);
        self::assertCount(0, $this->sentMail());
    }

    public function testEmailAsUsernameResolves(): void
    {
        $this->callReset('jane@example.test');

        self::assertCount(1, $this->sentMail());
        self::assertSame('jane@example.test', $this->sentMail()[0]['to']);
    }

    public function testEmailContainsUsernameSiteIpAndOtp(): void
    {
        $this->callReset('jane');

        $message = $this->sentMail()[0]['message'];
        self::assertStringContainsString('https://example.test/', $message);
        self::assertStringContainsString('Username: jane', $message);
        self::assertStringContainsString('198.51.100.7', $message);
        self::assertNotSame('', $this->otpFromMessage($message));
    }

    public function testOtpFromEmailVerifiesAgainstMeta(): void
    {
        $this->callReset('jane');

        $code = $this->otpFromMessage($this->sentMail()[0]['message']);
        self::assertNotSame('', $code);

        $user = $this->user();
        self::assertSame(true, PasswordResetCode::verify($user, $code));
    }

    public function testResetKeyStoredForDeepLinkFallback(): void
    {
        $this->callReset('jane');

        $key = $GLOBALS['__sjwt_reset_keys']['jane']['key'] ?? '';
        self::assertNotSame('', $key);
        self::assertSame($key, get_userdata(42)->user_activation_key);

        $message = $this->sentMail()[0]['message'];
        self::assertStringContainsString(
            '<https://example.test/wp-login.php?action=rp&key=' . $key . '&login=jane>',
            $message
        );
    }

    public function testResetUrlTemplateReplacesFallbackDeepLink(): void
    {
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY]['reset_url_template'] = 'myapp://reset?k={key}&u={login}';
        Config::flushCache();

        $this->callReset('jane');

        $resetKey = $GLOBALS['__sjwt_reset_keys']['jane']['key'] ?? '';
        $message  = $this->sentMail()[0]['message'];

        self::assertStringContainsString('myapp://reset?k=' . $resetKey . '&u=jane', $message);
        self::assertStringNotContainsString('wp-login.php?action=rp', $message);
    }

    public function testMailFailureDropsTheOtp(): void
    {
        add_filter('wp_mail', static function (array $args): array {
            $args['do_not_send'] = true;
            return $args;
        });

        $response = $this->callReset('jane');

        self::assertSame(200, $response->get_status());
        self::assertCount(0, $this->sentMail());
        self::assertSame('', get_user_meta(42, PasswordResetCode::META_KEY, true), 'stuck OTP cleared on mail failure');
    }

    public function testThrottledSendSkipsEmailButStill200(): void
    {
        [$maxEmails, $window] = $this->tokenService->getPasswordResetRateLimit();
        $bucket = 'sja_rl_password_reset_' . md5(strtolower((string) ($_SERVER['REMOTE_ADDR'] ?? '')));
        $GLOBALS['__sjwt_transients'][$bucket] = ['e' => 0, 'v' => $maxEmails];

        $response = $this->callReset('jane');

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset', $response->get_data()['code']);
        self::assertCount(0, $this->sentMail());
        self::assertSame($maxEmails, (int) get_transient($bucket), 'skipped send does not bump the bucket');
    }

    public function testAllowPasswordResetFilterBlocksSend(): void
    {
        add_filter('allow_password_reset', static function (): bool {
            return false;
        });

        $response = $this->callReset('jane');

        self::assertSame(200, $response->get_status());
        self::assertSame('jwt_auth_password_reset', $response->get_data()['code']);
        self::assertCount(0, $this->sentMail());
    }

    public function testLostpasswordPostActionFiresOnlyForKnownUser(): void
    {
        $fired = [];
        add_action('lostpassword_post', static function () use (&$fired): void {
            $fired[] = 'lostpassword_post';
        });

        $this->callReset('no-such-user');
        self::assertSame([], $fired, 'unknown user: no actions fire');

        $this->callReset('jane');
        self::assertSame(['lostpassword_post'], $fired);
    }

    public function testTitleFilterCanRenameSubject(): void
    {
        add_filter('retrieve_password_title', static function (): string {
            return 'Your reset code';
        });

        $this->callReset('jane');

        self::assertSame('Your reset code', $this->sentMail()[0]['subject']);
    }
}
