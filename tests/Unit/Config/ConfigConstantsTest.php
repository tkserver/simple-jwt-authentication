<?php
/**
 * Config constant-based (wp-config.php) behavior.
 *
 * Each test defines its own runtime constants; the suite runs with
 * processIsolation, so definitions never leak between tests (PHP constants
 * cannot be undefined).
 *
 * Task 1.1 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\Config;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;

final class ConfigConstantsTest extends TestCase
{
    protected function setUp(): void
    {
        // Included at runtime (top-level require cannot precede the namespace
        // declaration); idempotent. Provides get_option() + time constants.
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
    }

    private function setSettings(array $settings): void
    {
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = $settings;
        Config::flushCache();
    }

    /* ── secret key ── */

    public function testNewSecretConstantBeatsLegacyAndOption(): void
    {
        define(Config::SECRET_KEY_CONST, 'const-secret');
        define(Config::LEGACY_SECRET_KEY_CONST, 'legacy-secret');
        $this->setSettings(['secret_key' => 'option-secret']);

        self::assertSame('const-secret', Config::getSecretKey());
    }

    public function testLegacySecretConstantIsAcceptedFallback(): void
    {
        define(Config::LEGACY_SECRET_KEY_CONST, 'legacy-secret');
        $this->setSettings(['secret_key' => 'option-secret']);

        self::assertSame('legacy-secret', Config::getSecretKey());
    }

    public function testEmptyNewSecretConstantFallsThroughToLegacy(): void
    {
        define(Config::SECRET_KEY_CONST, '');
        define(Config::LEGACY_SECRET_KEY_CONST, 'legacy-secret');
        $this->setSettings(['secret_key' => 'option-secret']);

        self::assertSame('legacy-secret', Config::getSecretKey());
    }

    public function testEmptyNewSecretConstantFallsThroughToOption(): void
    {
        define(Config::SECRET_KEY_CONST, '');
        $this->setSettings(['secret_key' => 'option-secret']);

        self::assertSame('option-secret', Config::getSecretKey());
    }

    public function testSecretKeyNullWhenNothingConfigured(): void
    {
        self::assertNull(Config::getSecretKey());
    }

    /* ── CORS ── */

    public function testCorsConstantStringFalseCoercesCorrectly(): void
    {
        // Regression anchor for v2.0.1: (bool)'false' === true in the old code.
        define(Config::CORS_ENABLE_CONST, 'false');
        self::assertFalse(Config::isCorsEnabled());
    }

    public function testCorsConstantStringTrueCoercesCorrectly(): void
    {
        define(Config::CORS_ENABLE_CONST, 'true');
        self::assertTrue(Config::isCorsEnabled());
    }

    public function testCorsConstantIntegerOneCoercesCorrectly(): void
    {
        define(Config::CORS_ENABLE_CONST, 1);
        self::assertTrue(Config::isCorsEnabled());
    }

    public function testCorsConstantStringOffCoercesCorrectly(): void
    {
        define(Config::CORS_ENABLE_CONST, 'off');
        self::assertFalse(Config::isCorsEnabled());
    }

    public function testLegacyCorsConstantUsedWhenNewAbsent(): void
    {
        define(Config::LEGACY_CORS_ENABLE_CONST, 'true');
        self::assertTrue(Config::isCorsEnabled());
    }

    public function testNewCorsConstantBeatsLegacy(): void
    {
        define(Config::CORS_ENABLE_CONST, 'false');
        define(Config::LEGACY_CORS_ENABLE_CONST, 'true');
        self::assertFalse(Config::isCorsEnabled());
    }

    /* ── isGlobalDefined (admin "locked by wp-config" detection) ── */

    public function testIsGlobalDefinedWhenNewSecretDefined(): void
    {
        define(Config::SECRET_KEY_CONST, 'x');
        self::assertTrue(Config::isGlobalDefined(Config::SECRET_KEY_CONST));
    }

    public function testIsGlobalDefinedSecretViaLegacy(): void
    {
        define(Config::LEGACY_SECRET_KEY_CONST, 'x');
        self::assertTrue(Config::isGlobalDefined(Config::SECRET_KEY_CONST));
    }

    public function testIsGlobalDefinedFalseWhenNothingDefined(): void
    {
        self::assertFalse(Config::isGlobalDefined(Config::SECRET_KEY_CONST));
        self::assertFalse(Config::isGlobalDefined(Config::CORS_ENABLE_CONST));
    }

    public function testIsGlobalDefinedCorsViaLegacy(): void
    {
        define(Config::LEGACY_CORS_ENABLE_CONST, 'true');
        self::assertTrue(Config::isGlobalDefined(Config::CORS_ENABLE_CONST));
    }

    public function testIsGlobalDefinedUnknownConstantIsFalse(): void
    {
        self::assertFalse(Config::isGlobalDefined('NOT_A_REAL_CONSTANT'));
    }

    /* ── reset URL template ── */

    public function testResetUrlTemplateConstantUsedEvenWhenOptionSet(): void
    {
        define(Config::RESET_URL_TEMPLATE_CONST, 'myapp://reset?key={key}&login={login}');
        $this->setSettings(['reset_url_template' => 'https://web.example/reset']);

        self::assertSame('myapp://reset?key={key}&login={login}', Config::getResetUrlTemplate());
    }

    public function testResetUrlTemplateEmptyConstantIsNull(): void
    {
        define(Config::RESET_URL_TEMPLATE_CONST, '');
        $this->setSettings(['reset_url_template' => 'https://web.example/reset']);

        self::assertNull(Config::getResetUrlTemplate());
    }

    /* ── reset key max age ── */

    public function testResetKeyMaxAgeHoursConstant(): void
    {
        define(Config::RESET_KEY_MAX_AGE_CONST, '12');
        self::assertSame(12, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeHoursConstantNegativeClamped(): void
    {
        define(Config::RESET_KEY_MAX_AGE_CONST, '-3');
        self::assertSame(0, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeHoursConstantZero(): void
    {
        define(Config::RESET_KEY_MAX_AGE_CONST, '0');
        self::assertSame(0, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeSecondsConstant(): void
    {
        define(Config::RESET_KEY_MAX_AGE_CONST, '24');
        self::assertSame(24 * HOUR_IN_SECONDS, Config::getResetKeyMaxAge());
    }
}
