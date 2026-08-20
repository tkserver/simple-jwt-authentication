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
        if (defined(self::SECRET_KEY_CONST)) {
            return constant(self::SECRET_KEY_CONST);
        }
        $settings = self::getSettings();
        return $settings['secret_key'] ?? null;
    }

    public static function isCorsEnabled(): bool
    {
        if (defined(self::CORS_ENABLE_CONST)) {
            return self::parseBool(constant(self::CORS_ENABLE_CONST));
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
        return defined($constName);
    }

    /**
     * Reset cached settings (call after saving options).
     */
    public static function flushCache(): void
    {
        self::$cached = null;
    }
}
