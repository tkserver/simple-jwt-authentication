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

        add_settings_section(
            'simple_jwt_auth_reset_section',
            __('Password reset (mobile apps)', 'simple-jwt-authentication'),
            fn() => $this->renderResetSectionDescription(),
            self::PAGE_SLUG
        );

        add_settings_field(
            'reset_url_template',
            __('Reset URL Template', 'simple-jwt-authentication'),
            fn() => $this->renderResetUrlTemplateField(),
            self::PAGE_SLUG,
            'simple_jwt_auth_reset_section'
        );

        add_settings_field(
            'reset_key_max_age_hours',
            __('Reset Key Max Age (hours)', 'simple-jwt-authentication'),
            fn() => $this->renderResetKeyMaxAgeField(),
            self::PAGE_SLUG,
            'simple_jwt_auth_reset_section'
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

        if (isset($input['reset_url_template'])) {
            // sanitize_text_field is safe here: it strips tags and extra
            // whitespace but preserves the {key}/{login} placeholders and the
            // URL characters a deep link template needs.
            $settings['reset_url_template'] = sanitize_text_field(wp_unslash($input['reset_url_template']));
        }

        if (isset($input['reset_key_max_age_hours'])) {
            $settings['reset_key_max_age_hours'] = max(0, (int) $input['reset_key_max_age_hours']);
        }

        Config::flushCache();
        return $settings;
    }

    private function renderSectionDescription(): void
    {
        echo sprintf(
            /* translators: 1 and 2: wp-config.php code examples */
            __('This is all you need to start using JWT authentication.<br /> You can also specify these in wp-config.php instead using %1$s %2$s', 'simple-jwt-authentication'),
            "<br /><br /><code>define('SIMPLE_JWT_AUTHENTICATION_SECRET_KEY', 'YOURKEY');</code>"
            . "<br /><small>(also accepts legacy <code>JWT_AUTH_SECRET_KEY</code>)</small>",
            "<br /><br /><code>define('SIMPLE_JWT_AUTHENTICATION_CORS_ENABLE', true);</code>"
            . "<br /><small>(also accepts legacy <code>JWT_AUTH_CORS_ENABLE</code>)</small>"
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

    private function renderResetSectionDescription(): void
    {
        echo sprintf(
            /* translators: %s: code example of a deep link template */
            __('For mobile apps, point the emailed reset link at your app instead of the WordPress web reset form. The placeholders %s are filled in with the reset key and username. Leave the template empty to keep the default wp-login.php link.', 'simple-jwt-authentication'),
            '<code>{key}</code> and <code>{login}</code>'
        );
    }

    private function renderResetUrlTemplateField(): void
    {
        $template  = (string) (Config::getResetUrlTemplate() ?? '');
        $isGlobal  = Config::isGlobalDefined(Config::RESET_URL_TEMPLATE_CONST);
        include __DIR__ . '/Views/Settings/reset-url-template.php';
    }

    private function renderResetKeyMaxAgeField(): void
    {
        $maxAge    = Config::getResetKeyMaxAgeHours();
        $isGlobal  = Config::isGlobalDefined(Config::RESET_KEY_MAX_AGE_CONST);
        include __DIR__ . '/Views/Settings/reset-key-max-age.php';
    }

    private function renderPage(): void
    {
        include __DIR__ . '/Views/Settings/page.php';
    }
}
