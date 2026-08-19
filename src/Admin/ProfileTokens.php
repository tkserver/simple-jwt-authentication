<?php

declare(strict_types=1);

namespace SimpleJwtAuth\Admin;

use SimpleJwtAuth\TokenService;
use WP_User;

/**
 * Adds token management UI to the user profile page.
 */
final class ProfileTokens
{
    private TokenService $tokenService;

    public function __construct(TokenService $tokenService)
    {
        $this->tokenService = $tokenService;
    }

    public function register(): void
    {
        add_action('admin_notices', fn() => $this->renderNotices());
        add_action('edit_user_profile', fn($user) => $this->renderTokenUi($user), 20);
        add_action('show_user_profile', fn($user) => $this->renderTokenUi($user), 20);
        add_action('edit_user_profile', fn($user) => $this->handleRevoke($user));
        add_action('show_user_profile', fn($user) => $this->handleRevoke($user));
        add_action('edit_user_profile', fn($user) => $this->handleRevokeAll($user));
        add_action('show_user_profile', fn($user) => $this->handleRevokeAll($user));
        add_action('edit_user_profile', fn($user) => $this->handleRemoveExpired($user));
        add_action('show_user_profile', fn($user) => $this->handleRemoveExpired($user));
    }

    private function renderNotices(): void
    {
        if (empty($_GET['jwtupdated'])) {
            return;
        }

        $message = match(true) {
            !empty($_GET['revoked']) && $_GET['revoked'] === 'all'
                => __('All tokens have been revoked.', 'simple-jwt-authentication'),
            !empty($_GET['revoked'])
                => sprintf(
                    __('The token %s has been revoked.', 'simple-jwt-authentication'),
                    sanitize_text_field(wp_unslash($_GET['revoked']))
                ),
            !empty($_GET['removed'])
                => __('All expired tokens have been removed.', 'simple-jwt-authentication'),
            default => null,
        };

        if ($message !== null) {
            echo sprintf('<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html($message));
        }
    }

    private function renderTokenUi(WP_User $user): void
    {
        if (!current_user_can('edit_user')) {
            return;
        }

        $tokens = get_user_meta($user->ID, 'jwt_data', true);
        if (!is_array($tokens)) {
            $tokens = [];
        }

        include __DIR__ . '/Views/user-token-ui.php';
    }

    private function handleRevoke(WP_User $user): void
    {
        if (!current_user_can('edit_user') || empty($_GET['revoke_token'])) {
            return;
        }

        check_admin_referer('jwt_revoke_token');

        $requestToken = sanitize_text_field(wp_unslash($_GET['revoke_token']));
        $tokens       = get_user_meta($user->ID, 'jwt_data', true);

        if (is_array($tokens)) {
            foreach ($tokens as $key => $token) {
                if (hash_equals($token['uuid'], $requestToken)) {
                    unset($tokens[$key]);
                    update_user_meta($user->ID, 'jwt_data', $tokens);
                    break;
                }
            }
        }

        $this->redirectWithNotice('revoke_token', ['revoked' => $requestToken]);
    }

    private function handleRevokeAll(WP_User $user): void
    {
        if (!current_user_can('edit_user') || empty($_GET['revoke_all_tokens'])) {
            return;
        }

        check_admin_referer('jwt_revoke_all_tokens');

        delete_user_meta($user->ID, 'jwt_data');

        $this->redirectWithNotice('revoke_all_tokens', ['revoked' => 'all']);
    }

    private function handleRemoveExpired(WP_User $user): void
    {
        if (!current_user_can('edit_user') || empty($_GET['remove_expired_tokens'])) {
            return;
        }

        check_admin_referer('jwt_remove_expired_tokens');

        $this->tokenService->removeExpiredTokens($user->ID);

        $this->redirectWithNotice('remove_expired_tokens', ['removed' => 'all']);
    }

    private function redirectWithNotice(string $removeArg, array $noticeArgs): void
    {
        $base = wp_get_referer() ?: (wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
        $base = remove_query_arg($removeArg, $base);
        $args = array_merge(['jwtupdated' => 1], $noticeArgs);
        wp_safe_redirect(add_query_arg($args, $base));
        exit;
    }
}
