<?php
/**
 * Auth middleware + bypass-route matcher (RestController).
 *
 * Regression anchors:
 *  - bypass routes must match exact path suffixes only (`/token/validate/custom`
 *    must NOT bypass) — v2.0.1 fix
 *  - both pretty permalinks and `?rest_route=` forms must honor Bearer — 2.1.1 fix
 *  - re-entry guard around determine_current_user (OOM recursion) — 2.1.1 fix
 *
 * Task 1.5 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\Rest;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleJwtAuth\Rest\RestController;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;
use WP_Error;
use WP_User;

final class RestControllerMiddlewareTest extends TestCase
{
    private const NAMESPACE = 'simple-jwt-authentication/v1';
    private const SECRET    = 'sjwt-testing-secret-key-0123456789abcdef';

    private TokenService $tokenService;
    private RestController $controller;

    protected function setUp(): void
    {
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
        $GLOBALS['__sjwt_options_store'][\SimpleJwtAuth\Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        \SimpleJwtAuth\Config::flushCache();

        $this->tokenService = new TokenService();
        $this->controller   = new RestController(
            self::NAMESPACE,
            $this->tokenService,
            new TokenEndpoint($this->tokenService),
        );
    }

    private function user(): WP_User
    {
        return new WP_User([
            'ID'          => 42,
            'user_email'  => 'jane@example.test',
            'user_login'  => 'jane',
            'user_nicename' => 'jane',
            'display_name' => 'Jane',
        ]);
    }

    private function withValidToken(): string
    {
        $token = $this->tokenService->generateToken($this->user())['token'];
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        return $token;
    }

    private function invokePrivate(string $method, string $uri): mixed
    {
        $_SERVER['REQUEST_URI'] = $uri;
        $ref = new \ReflectionMethod($this->controller, $method);
        return $ref->invoke($this->controller, $uri);
    }

    /* ── bypass-route matcher matrix (exact suffix matching only) ── */

    public static function bypassRouteCases(): array
    {
        $base = '/wp-json/simple-jwt-authentication/v1/token';

        return [
            // pretty permalinks
            [$base, true],
            [$base . '/', true],                                       // trailing slash
            [$base . '/validate', true],
            [$base . '/resetpassword', true],
            [$base . '/resetpassword/complete', true],
            [$base . '/validate/custom', false],                       // must NOT bypass
            [$base . '/resetpassword/complete/extra', false],
            [$base . '/xyz', false],
            ['/wp-json/simple-jwt-authentication/v1/other/route', false],
            ['/wp-json/wp/v2/posts', false],

            // non-pretty permalinks (?rest_route=)
            ['/index.php?rest_route=/simple-jwt-authentication/v1/token', true],
            ['/index.php?rest_route=%2Fsimple-jwt-authentication%2Fv1%2Ftoken', true], // encoded
            ['/index.php?rest_route=/simple-jwt-authentication/v1/token&foo=bar', true],
            ['/index.php?rest_route=/simple-jwt-authentication/v1/token/validate/custom', false],
            ['/index.php?rest_route=/wp/v2/posts', false],
        ];
    }

    #[DataProvider('bypassRouteCases')]
    public function testBypassRouteMatcherIsExactSuffix(string $uri, bool $expected): void
    {
        self::assertSame($expected, $this->invokePrivate('isBypassRoute', $uri), $uri);
    }

    /* ── public middleware behavior ── */

    public function testNonRestUriNeverAuthenticates(): void
    {
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/2026/a-regular-page';

        self::assertFalse($this->controller->determineCurrentUser(false));
        self::assertNull($this->tokenService->getJwtError());
    }

    public function testBypassRouteSkipsMiddlewareEvenWithBearer(): void
    {
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/wp-json/simple-jwt-authentication/v1/token';

        self::assertFalse($this->controller->determineCurrentUser(false));
        self::assertNull($this->tokenService->getJwtError());
    }

    public function testRestRouteWithoutHeaderLeavesUserAlone(): void
    {
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertFalse($this->controller->determineCurrentUser(false));
        self::assertNull($this->tokenService->getJwtError());
    }

    public function testPrettyRestRouteValidatesBearer(): void
    {
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertSame(42, $this->controller->determineCurrentUser(false));
    }

    public function testNonPrettyRestRouteStillValidatesBearer(): void
    {
        // Regression anchor (2.1.1): Bearer was ignored entirely on
        // non-pretty permalink installs.
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/index.php?rest_route=/wp/v2/posts';

        self::assertSame(42, $this->controller->determineCurrentUser(false));
    }

    public function testInvalidBearerSetsJwtErrorAndLeavesUser(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer this-is-not-a-real-token.at.all';
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertFalse($this->controller->determineCurrentUser(false));

        $error = $this->tokenService->getJwtError();
        self::assertInstanceOf(WP_Error::class, $error);
        self::assertSame('jwt_auth_invalid_token', $error->get_error_code());
    }

    public function testValidBearerBeatsEarlierUser(): void
    {
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertSame(42, $this->controller->determineCurrentUser(5));
    }

    public function testReEntryGuardShortCircuits(): void
    {
        // Regression anchor (2.1.1): nested determine_current_user must not
        // recurse (locale lookup via __() inside validateToken caused OOM).
        $this->withValidToken();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        $prop = new ReflectionProperty($this->controller, 'determiningUser');
        $prop->setAccessible(true);
        $prop->setValue($this->controller, true);

        self::assertFalse($this->controller->determineCurrentUser(false));
        self::assertNull($this->tokenService->getJwtError(), 'no validation ran inside the guard');
    }

    public function testPreDispatchTranslatesStoredJwtError(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer this-is-not-a-real-token.at.all';
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        $this->controller->determineCurrentUser(false);
        $stored = $this->tokenService->getJwtError();
        self::assertInstanceOf(WP_Error::class, $stored);

        $translated = $this->controller->preDispatch(null);
        self::assertInstanceOf(WP_Error::class, $translated);
        self::assertSame($stored->get_error_code(), $translated->get_error_code());
        self::assertNotSame('', $translated->get_error_message());
    }

    public function testPreDispatchPassesThroughWhenNoJwtError(): void
    {
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertNull($this->controller->preDispatch(null));
    }
}
