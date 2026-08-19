<?php

declare(strict_types=1);

namespace SimpleJwtAuth\Admin;

use SimpleJwtAuth\Config;

/**
 * Registers the admin settings page under Settings → Simple JWT Authentication.
 */
final class SettingsPage
{
    private const PAGE_SLUG = 'simple_jwt_authentication';
    private const OPTION_GROUP = 'simple_jwt_authentication';

    public function register(): void
    {
        add_action('admin_menu', fn() => $this->addMenu());
        add_action('admin_init', fn() => $this->initSettings());
    }

    private function addMenu(): void
    {
        add_options_page(
            __('Simple JWT Authentication', 'simple-jwt-authentication'),
            __('Simple JWT Authentication', 'simple-jwt-authentication'),
            'manage_options',
            self::PAGE_SLUG,
            fn() => $this->renderPage()
        );
    }

    private function initSettings(): void
    {
        register_setting(self::OPTION_GROUP, Config::OPTION_KEY, [
            'sanitize_callback' => fn(array $input) => $this->sanitize($input),
        ]);

        add_settings_section(
            'simple_jwt_auth_section',
            __('Basic configuration', 'simple-jwt-authentication'),
            fn() => $this->renderSectionDescription(),
            self::PAGE_SLUG
        );

        add_settings_field(
            'secret_key',
            __('Secret Key', 'simple-jwt-authentication'),
            fn() => $this->renderSecretKeyField(),
            self::PAGE_SLUG,
            'simple_jwt_auth_section'
        );

        add_settings_field(
            'enable_cors',
            sprintf(__('Enable %s', 'simple-jwt-authentication'), '<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS" target="_blank" rel="noopener">CORS</a>'),
            fn() => $this->renderCorsField(),
            self::PAGE_SLUG,
            'simple_jwt_auth_section'
        );
    }

    private function sanitize(array $input): array
    {
        $settings = [];

        if (isset($input['secret_key'])) {
            $settings['secret_key'] = sanitize_text_field($input['secret_key']);
        }

        if (isset($input['enable_cors'])) {
            $settings['enable_cors'] = (bool) $input['enable_cors'];
        }

        Config::flushCache();
        return $settings;
    }

    private function renderSectionDescription(): void
    {
        echo sprintf(
            /* translators: 1 and 2: wp-config.php code examples */
            __('This is all you need to start using JWT authentication.<br /> You can also specify these in wp-config.php instead using %1$s %2$s', 'simple-jwt-authentication'),
            "<br /><br /><code>define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', 'YOURKEY');</code>",
            "<br /><br /><code>define('SIMPLE_JWT_AUTHENTICATION_CORS_ENABLE', true);</code>"
        );
    }

    private function renderSecretKeyField(): void
    {
        $secretKey = Config::getSecretKey();
        $isGlobal  = Config::isGlobalDefined(Config::SECRET_KEY_CONST);
        include __DIR__ . '/Views/Settings/secret-key.php';
    }

    private function renderCorsField(): void
    {
        $enableCors = Config::isCorsEnabled();
        $isGlobal   = Config::isGlobalDefined(Config::CORS_ENABLE_CONST);
        include __DIR__ . '/Views/Settings/enable-cors.php';
    }

    private function renderPage(): void
    {
        include __DIR__ . '/Views/Settings/page.php';
    }
}
