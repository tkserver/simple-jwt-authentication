<?php
/**
 * Config option-based behavior (settings stored in the DB via get_option).
 * Uses the guarded lite stubs for get_option() + time constants.
 *
 * Task 1.1 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\Config;

use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;

final class ConfigOptionsTest extends TestCase
{
    protected function setUp(): void
    {
        // Included at runtime: a top-level require cannot precede the
        // namespace declaration. require_once keeps it idempotent.
        require_once __DIR__ . '/../../helpers/wp-lite-stubs.php';

        \SjwtTestState::reset();
    }

    private function setSettings(array $settings): void
    {
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = $settings;
        Config::flushCache();
    }

    public function testSecretKeyFromOption(): void
    {
        $this->setSettings(['secret_key' => 'option-secret']);
        self::assertSame('option-secret', Config::getSecretKey());
    }

    public function testSecretKeyEmptyOptionIsNull(): void
    {
        $this->setSettings(['secret_key' => '']);
        self::assertNull(Config::getSecretKey());
    }

    public function testSecretKeyMissingIsNull(): void
    {
        self::assertNull(Config::getSecretKey());
    }

    public function testSecretKeyNonStringIsNull(): void
    {
        $this->setSettings(['secret_key' => 12345]);
        self::assertNull(Config::getSecretKey());
    }

    public function testResetUrlTemplateFromOption(): void
    {
        $tpl = 'myapp://reset-password?key={key}&login={login}';
        $this->setSettings(['reset_url_template' => $tpl]);
        self::assertSame($tpl, Config::getResetUrlTemplate());
    }

    public function testResetUrlTemplateEmptyIsNull(): void
    {
        $this->setSettings(['reset_url_template' => '']);
        self::assertNull(Config::getResetUrlTemplate());
    }

    public function testResetKeyMaxAgeHoursFromOption(): void
    {
        $this->setSettings(['reset_key_max_age_hours' => '24']);
        self::assertSame(24, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeHoursNegativeClampedToZero(): void
    {
        $this->setSettings(['reset_key_max_age_hours' => '-5']);
        self::assertSame(0, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeHoursNonNumericIsZero(): void
    {
        $this->setSettings(['reset_key_max_age_hours' => 'abc']);
        self::assertSame(0, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeHoursMissingIsZero(): void
    {
        self::assertSame(0, Config::getResetKeyMaxAgeHours());
    }

    public function testResetKeyMaxAgeSeconds(): void
    {
        $this->setSettings(['reset_key_max_age_hours' => '24']);
        self::assertSame(24 * HOUR_IN_SECONDS, Config::getResetKeyMaxAge());
    }

    public function testGetSettingsReturnsEmptyArrayWhenNothingStored(): void
    {
        self::assertSame([], Config::getSettings());
    }

    public function testGetSettingsCachesUntilFlush(): void
    {
        $this->setSettings(['secret_key' => 'first']);
        self::assertSame('first', Config::getSettings()['secret_key']);

        // Change the underlying option: the static cache must not pick it up…
        $GLOBALS['__sjwt_options_store'][Config::OPTION_KEY] = ['secret_key' => 'second'];
        self::assertSame('first', Config::getSettings()['secret_key']);

        // …until flushCache().
        Config::flushCache();
        self::assertSame('second', Config::getSettings()['secret_key']);
    }

    /* ── CORS from options (no wp-config constants present) ── */

    public function testCorsEnabledFromOptionStringFalse(): void
    {
        // Regression anchor for v2.0.1: string 'false' must coerce to false.
        $this->setSettings(['enable_cors' => 'false']);
        self::assertFalse(Config::isCorsEnabled());
    }

    public function testCorsEnabledFromOptionStringTrue(): void
    {
        $this->setSettings(['enable_cors' => 'true']);
        self::assertTrue(Config::isCorsEnabled());
    }

    public function testCorsEnabledFromOptionBool(): void
    {
        $this->setSettings(['enable_cors' => true]);
        self::assertTrue(Config::isCorsEnabled());
    }

    public function testCorsDisabledByDefaultWhenNothingStored(): void
    {
        self::assertFalse(Config::isCorsEnabled());
    }
}
