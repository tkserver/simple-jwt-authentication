<?php

/**
 * Plugin Name: Simple JWT Authentication
 * Plugin URI:  https://github.com/jonathan-dejong/simple-jwt-authentication
 * Description: Extends the WP REST API using JSON Web Tokens Authentication as an authentication method.
 * Version:     2.0.0
 * Requires at least: 6.4
 * Requires PHP: 8.2
 * Author:      Jonathan de Jong
 * Author URI:  https://github.com/jonathan-dejong
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: simple-jwt-authentication
 * Domain Path: /languages
 *
 * @since 1.0
 */

if (!defined('WPINC')) {
    die;
}

require_once __DIR__ . '/includes/vendor/autoload.php';
require_once __DIR__ . '/src/Plugin.php';

register_activation_hook(__FILE__, [\SimpleJwtAuth\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\SimpleJwtAuth\Plugin::class, 'deactivate']);

new \SimpleJwtAuth\Plugin();
