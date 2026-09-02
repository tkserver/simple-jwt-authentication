<?php
/**
 * Namespace-scoped shim for PHP built-in collisions.
 *
 * `header()` is a PHP core function, so a *global* stub can never take
 * precedence (function_exists('header') is always true). Unqualified calls
 * inside `namespace SimpleJwtAuth\Rest;` resolve to a namespace-scoped
 * function first, though — so the plugin's CORS header lines are recorded
 * here instead of being swallowed by PHP's real header().
 */

namespace SimpleJwtAuth\Rest;

if (!function_exists('SimpleJwtAuth\\Rest\\header')) {
    function header(string $headerLine, bool $replace = true, int $responseCode = 0): void
    {
        // WP's header() takes the full "Name: value" line.
        if (!str_contains($headerLine, ':')) {
            return;
        }
        [$name, $value] = explode(':', $headerLine, 2);
        $GLOBALS['__sjwt_headers'][trim($name)] = trim($value);
    }
}
