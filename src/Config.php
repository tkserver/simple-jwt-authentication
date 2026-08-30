<?php

declare(strict_types=1);

namespace SimpleJwtAuth;

/**
 * Centralized configuration accessor.
 *
 * Values can be set via wp-config.php constants or the admin settings page (stored in options).
 * Constants take precedence over stored options.
 */
final class Config
{
    public const SECRET_KEY_CONST = 'SIMPLE_JWT_AUTHENTICATION_SECRET_KEY';
    public const CORS_ENABLE_CONST = 'SIMPLE_JWT_AUTHENTICATION_CORS_ENABLE';
    public const RESET_URL_TEMPLATE_CONST = 'SIMPLE_JWT_AUTHENTICATION_RESET_URL_TEMPLATE';
    public const RESET_KEY_MAX_AGE_CONST = 'SIMPLE_JWT_AUTHENTICATION_RESET_KEY_MAX_AGE';

    /**
     * Legacy wp-config constants used by some forks / older JWT plugins
     * (e.g. jwt-authentication-for-wp-rest-api). Accepted as fallbacks so
     * existing production configs keep working after the v2 rename.
     */
    public const LEGACY_SECRET_KEY_CONST = 'JWT_AUTH_SECRET_KEY';
    public const LEGACY_CORS_ENABLE_CONST = 'JWT_AUTH_CORS_ENABLE';

    public const OPTION_KEY = 'simple_jwt_authentication_settings';

    private static ?array $cached = null;

    public static function getSettings(): array
    {
        if (self::$cached === null) {
            self::$cached = get_option(self::OPTION_KEY, []);
        }
        return self::$cached;
    }

    public static function getSecretKey(): ?string
    {
        $fromConst = self::constantString(self::SECRET_KEY_CONST)
            ?? self::constantString(self::LEGACY_SECRET_KEY_CONST);
        if ($fromConst !== null) {
            return $fromConst;
        }

        $settings = self::getSettings();
        $fromOpt  = $settings['secret_key'] ?? null;
        if (!is_string($fromOpt) || $fromOpt === '') {
            return null;
        }

        return $fromOpt;
    }

    public static function isCorsEnabled(): bool
    {
        if (defined(self::CORS_ENABLE_CONST)) {
            return self::parseBool(constant(self::CORS_ENABLE_CONST));
        }
        if (defined(self::LEGACY_CORS_ENABLE_CONST)) {
            return self::parseBool(constant(self::LEGACY_CORS_ENABLE_CONST));
        }
        $settings = self::getSettings();
        return self::parseBool($settings['enable_cors'] ?? false);
    }

    /**
     * Coerce a setting/constant value to a bool. Handles string forms like
     * 'false', '0', 'off' that a bare (bool) cast would treat as true.
     */
    public static function parseBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_string($value)) {
            return !in_array(strtolower($value), ['0', 'false', 'no', 'off', ''], true);
        }
        return (bool) $value;
    }

    public static function isGlobalDefined(string $constName): bool
    {
        if (defined($constName)) {
            return true;
        }

        // Admin UI treats the secret/CORS fields as "locked by wp-config" when
        // either the new or the legacy constant is present.
        if ($constName === self::SECRET_KEY_CONST) {
            return defined(self::LEGACY_SECRET_KEY_CONST);
        }
        if ($constName === self::CORS_ENABLE_CONST) {
            return defined(self::LEGACY_CORS_ENABLE_CONST);
        }

        return false;
    }

    /**
     * Read a non-empty string constant, or null if missing/blank.
     */
    private static function constantString(string $name): ?string
    {
        if (!defined($name)) {
            return null;
        }
        $value = constant($name);
        if (!is_string($value) || $value === '') {
            return null;
        }
        return $value;
    }

    /**
     * Custom URL template for the emailed password reset link, e.g. a mobile
     * app deep link: `myapp://reset-password?key={key}&login={login}`.
     *
     * Supported placeholders: `{key}` and `{login}`.
     *
     * @return string|null Null when no template is configured (falls back to
     *                     the core wp-login.php?action=rp URL).
     */
    public static function getResetUrlTemplate(): ?string
    {
        if (defined(self::RESET_URL_TEMPLATE_CONST)) {
            $value = (string) constant(self::RESET_URL_TEMPLATE_CONST);

            return $value !== '' ? $value : null;
        }

        $settings = self::getSettings();
        $value    = (string) ($settings['reset_url_template'] ?? '');

        return $value !== '' ? $value : null;
    }

    /**
     * Maximum age for a password reset key, in hours. 0 defers to WordPress
     * core's own default expiration (24h as of WP 5.7+, via the
     * `password_reset_expiration` filter).
     */
    public static function getResetKeyMaxAgeHours(): int
    {
        if (defined(self::RESET_KEY_MAX_AGE_CONST)) {
            return max(0, (int) constant(self::RESET_KEY_MAX_AGE_CONST));
        }

        $settings = self::getSettings();

        return max(0, (int) ($settings['reset_key_max_age_hours'] ?? 0));
    }

    /**
     * Maximum age for a password reset key, in seconds. 0 defers to WP
     * core's own default expiration.
     */
    public static function getResetKeyMaxAge(): int
    {
        return self::getResetKeyMaxAgeHours() * HOUR_IN_SECONDS;
    }

    /**
     * Reset cached settings (call after saving options).
     */
    public static function flushCache(): void
    {
        self::$cached = null;
    }
}
