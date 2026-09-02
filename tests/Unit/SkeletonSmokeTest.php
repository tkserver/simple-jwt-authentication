<?php
/**
 * Smoke test proving the PHPUnit wiring works: the bootstrap loads both
 * autoloaders and the PSR-4 mapping for SimpleJwtAuth\Tests\ is functional.
 *
 * Task 0.2 (TEST-SUITE-TASKS.md). Harmless to keep long-term — it also guards
 * the harness against future autoloader regressions.
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class SkeletonSmokeTest extends TestCase
{
    public function testRuntimeAutoloaderResolvesPluginClasses(): void
    {
        $this->assertTrue(
            class_exists(\SimpleJwtAuth\Config::class),
            'includes/vendor autoload.php must expose the plugin classes'
        );
    }

    public function testRuntimeAutoloaderResolvesJwtLibrary(): void
    {
        $this->assertTrue(
            class_exists(\Firebase\JWT\JWT::class),
            'includes/vendor autoload.php must expose firebase/php-jwt'
        );
    }

    public function testHarnessAutoloaderMapsTestsNamespace(): void
    {
        $this->assertTrue(
            class_exists(self::class),
            'tests/vendor autoload.php must map SimpleJwtAuth\\Tests\\'
        );
    }
}
