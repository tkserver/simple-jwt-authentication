<?php
/**
 * PHPUnit bootstrap for the Simple JWT Authentication test suites.
 *
 * Loads, in order:
 *  1. the test-harness autoloader (tests/vendor) — PHPUnit + SimpleJwtAuth\Tests\*
 *  2. the plugin runtime autoloader (includes/vendor, committed) — firebase/php-jwt
 *     + the SimpleJwtAuth\* production classes
 *
 * Deliberately does NOT load WordPress: Phase 1 tasks are pure PHP. The
 * WP-dependent suite (tests/WP) wires its shim layer in tests/WP/shim-functions.php
 * (Phase 2) — see TEST-SUITE-TASKS.md.
 */

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';
require_once dirname(__DIR__) . '/includes/vendor/autoload.php';
