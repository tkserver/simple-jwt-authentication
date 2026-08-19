<?php

/**
 * Fired when the plugin is uninstalled.
 *
 * Cleans up options and user meta associated with the plugin.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('simple_jwt_authentication_settings');

$users = get_users(['fields' => 'ID']);
foreach ($users as $userId) {
    delete_user_meta($userId, 'jwt_data');
}
