<?php

declare(strict_types=1);

namespace SimpleJwtAuth;

use SimpleJwtAuth\Admin\ProfileTokens;
use SimpleJwtAuth\Admin\SettingsPage;
use SimpleJwtAuth\Rest\RestController;
use SimpleJwtAuth\Rest\TokenEndpoint;

/**
 * Main plugin orchestrator. Wires up all components.
 */
final class Plugin
{
    public const VERSION = '2.0.1';
    public const NAME    = 'simple-jwt-authentication';

    private readonly TokenService $tokenService;
    private readonly RestController $restController;
    private readonly TokenEndpoint $tokenEndpoint;

    public function __construct()
    {
        $this->tokenService  = new TokenService();
        $this->tokenEndpoint = new TokenEndpoint($this->tokenService);
        $namespace           = self::NAME . '/v1';
        $this->restController = new RestController($namespace, $this->tokenService, $this->tokenEndpoint);

        add_action('init', fn() => $this->loadTextdomain());

        if (is_admin()) {
            (new SettingsPage())->register();
            (new ProfileTokens($this->tokenService))->register();
        }
    }

    public static function activate(): void
    {
        // Reserved for future activation logic (e.g. creating default options).
    }

    public static function deactivate(): void
    {
        // Reserved for future deactivation logic.
    }

    private function loadTextdomain(): void
    {
        load_plugin_textdomain(
            self::NAME,
            false,
            dirname(plugin_basename(__FILE__)) . '/languages/'
        );
    }
}
