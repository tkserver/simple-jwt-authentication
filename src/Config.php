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
            return (bool) constant(self::CORS_ENABLE_CONST);
        }
        $settings = self::getSettings();
        return (bool) ($settings['enable_cors'] ?? false);
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
