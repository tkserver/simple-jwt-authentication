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

/*
 * Remove all stored token metadata in a single query instead of looping over
 * every user (which is very slow on large installations).
 */
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = 'jwt_data'");
