<?php
/**
 * Config::parseBool() coercion table — pure PHP, no WP surface needed.
 *
 * Regression anchor: v2.0.1 fixed `(bool) 'false' === true` for string CORS
 * constants. These cases pin that behavior down.
 *
 * Task 1.1 (TEST-SUITE-TASKS.md).
 */

declare(strict_types=1);

namespace SimpleJwtAuth\Tests\Unit\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleJwtAuth\Config;

final class ConfigParseBoolTest extends TestCase
{
    #[DataProvider('boolCases')]
    public function testCoercion(mixed $input, bool $expected): void
    {
        self::assertSame($expected, Config::parseBool($input));
    }

    public static function boolCases(): array
    {
        return [
            // bools pass through unchanged
            [true, true],
            [false, false],

            // string truthy forms
            ['true', true],
            ['TRUE', true],
            ['1', true],
            ['yes', true],
            ['on', true],
            ['enabled', true],
            ['2', true],

            // string falsy forms — a bare (bool) cast would make these true
            ['false', false],
            ['FALSE', false],
            ['False', false],
            ['0', false],
            ['no', false],
            ['off', false],
            ['', false],

            // other scalar/array coercion (same as (bool) cast)
            [1, true],
            [0, false],
            [1.5, true],
            [-1, true],
            [null, false],
            [[], false],
            [['x'], true],
        ];
    }
}
