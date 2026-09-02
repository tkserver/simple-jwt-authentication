<?php
/**
 * CORS support + OPTIONS preflight (RestController).
 *
 * Regression anchors:
 *  - `enable_cors: 'false'` must actually disable CORS (Config::parseBool)
 *  - preflight answers 204 and stops (wp_die) before WP routing
 *  - header list must not contain the bogus self-referential
 *    `Access-Control-Allow-Headers` entry
 *
 * Task 3.6 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\WP;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;
use SimpleJwtAuth\Rest\RestController;
use SimpleJwtAuth\Rest\TokenEndpoint;
use SimpleJwtAuth\TokenService;

final class RestControllerCorsTest extends TestCase
{
    private const SECRET = 'sjwt-testing-secret-key-0123456789abcdef';

    private RestController $controller;

    protected function setUp(): void
    {
        require_once __DIR__ . '/shim-functions.php';

        \SjwtTestState::reset();
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = ['secret_key' => self::SECRET];
        Config::flushCache();

        $tokenService = new TokenService();
        $this->controller = new RestController(
            'simple-jwt-authentication/v1',
            $tokenService,
            new TokenEndpoint($tokenService),
        );
    }

    private function enableCors(string|bool $value = true): void
    {
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY]['enable_cors'] = $value;
        Config::flushCache();
    }

    private function onNamespaceRoute(): void
    {
        $_SERVER['REQUEST_URI'] = '/wp-json/simple-jwt-authentication/v1/token';
    }

    public function testDisabledByDefaultSendsNothing(): void
    {
        $this->onNamespaceRoute();

        do_action('rest_api_init');
        do_action('init');

        self::assertSame([], $GLOBALS['__sjwt_headers'] ?? []);
        self::assertArrayNotHasKey('__sjwt_status_header', $GLOBALS);
        self::assertArrayNotHasKey('__sjwt_wp_died', $GLOBALS);
    }

    public function testParseBoolFalseDisablesCors(): void
    {
        // Regression: a bare (bool) cast would treat the string 'false' as true.
        $this->enableCors('false');
        $this->onNamespaceRoute();

        do_action('rest_api_init');
        do_action('init');

        self::assertSame([], $GLOBALS['__sjwt_headers'] ?? []);
    }

    public function testAddCorsSupportSetsDefaultHeaders(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();

        do_action('rest_api_init');

        $headers = $GLOBALS['__sjwt_headers'] ?? [];
        self::assertSame('*', $headers['Access-Control-Allow-Origin']);
        self::assertSame('Content-Type, Authorization', $headers['Access-Control-Allow-Headers']);
    }

    public function testAddCorsSupportIgnoresOtherRoutes(): void
    {
        $this->enableCors();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        do_action('rest_api_init');

        self::assertSame([], $GLOBALS['__sjwt_headers'] ?? []);
    }

    public function testCorsFiltersReflected(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();
        add_filter('jwt_auth_cors_allow_origin', static function (): string {
            return 'https://app.example.test';
        });
        add_filter('jwt_auth_cors_allow_headers', static function (): string {
            return 'Authorization';
        });

        do_action('rest_api_init');

        $headers = $GLOBALS['__sjwt_headers'] ?? [];
        self::assertSame('https://app.example.test', $headers['Access-Control-Allow-Origin']);
        self::assertSame('Authorization', $headers['Access-Control-Allow-Headers']);
    }

    public function testPreflightAnswers204AndStops(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();
        $_SERVER['REQUEST_METHOD'] = 'OPTIONS';

        do_action('init');

        self::assertSame(204, $GLOBALS['__sjwt_status_header'] ?? null);
        $headers = $GLOBALS['__sjwt_headers'] ?? [];
        self::assertSame('*', $headers['Access-Control-Allow-Origin']);
        self::assertSame('GET, POST, PUT, DELETE, OPTIONS', $headers['Access-Control-Allow-Methods']);
        self::assertSame('Content-Type, Authorization', $headers['Access-Control-Allow-Headers']);
        self::assertSame('86400', $headers['Access-Control-Max-Age']);
        self::assertArrayHasKey('__sjwt_wp_died', $GLOBALS, 'preflight must stop before WP routing');
    }

    public function testPreflightIgnoresNonOptionsRequests(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();
        $_SERVER['REQUEST_METHOD'] = 'GET';

        do_action('init');

        self::assertSame([], $GLOBALS['__sjwt_headers'] ?? []);
        self::assertArrayNotHasKey('__sjwt_status_header', $GLOBALS);
    }

    public function testPreflightIgnoresOtherRoutes(): void
    {
        $this->enableCors();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
        $_SERVER['REQUEST_METHOD'] = 'OPTIONS';

        do_action('init');

        self::assertSame([], $GLOBALS['__sjwt_headers'] ?? []);
    }

    public function testPreflightHeaderListNotSelfReferential(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();
        $_SERVER['REQUEST_METHOD'] = 'OPTIONS';

        do_action('init');

        $headers = (string) ($GLOBALS['__sjwt_headers']['Access-Control-Allow-Headers'] ?? '');
        self::assertStringContainsString('Authorization', $headers);
        self::assertStringContainsString('Content-Type', $headers);
        self::assertStringNotContainsString(
            'Access-Control-Allow-Headers',
            $headers,
            'regression: no bogus self-referential entry'
        );
    }

    public function testPreflightFiltersReflected(): void
    {
        $this->enableCors();
        $this->onNamespaceRoute();
        $_SERVER['REQUEST_METHOD'] = 'OPTIONS';
        add_filter('jwt_auth_cors_allow_origin', static function (): string {
            return 'https://app.example.test';
        });

        do_action('init');

        self::assertSame(
            'https://app.example.test',
            $GLOBALS['__sjwt_headers']['Access-Control-Allow-Origin']
        );
    }

    public function testLegacyConstantEnablesCors(): void
    {
        define(Config::LEGACY_CORS_ENABLE_CONST, 'true');
        $this->onNamespaceRoute();

        do_action('rest_api_init');

        self::assertSame('*', $GLOBALS['__sjwt_headers']['Access-Control-Allow-Origin'] ?? null);
    }
}
