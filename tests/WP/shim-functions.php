<?php
/**
 * WP shim library for the endpoint tests (tests/WP/).
 *
 * Built on top of the guarded lite stubs; every function and class here is
 * also guarded so that a real WP environment (or a future richer shim) wins
 * by simply being loaded first. State lives in `$GLOBALS['__sjwt_*']` keys,
 * which SjwtTestState::reset() clears generically.
 *
 * Task 2.2 / 2.3 (TEST-SUITE-TASKS.md).
 */

require_once __DIR__ . '/../helpers/wp-lite-stubs.php';
require_once __DIR__ . '/shim-ns-header.php';

/* ─── user store ──────────────────────────────────────────────────────── */

function sjwtAddUser(array $row): WP_User
{
    $row += [
        'ID'                  => 0,
        'user_login'          => '',
        'user_email'          => '',
        'user_nicename'       => '',
        'display_name'        => '',
        'user_pass'           => '',
        'user_activation_key' => '',
    ];
    $GLOBALS['__sjwt_users'][(int) $row['ID']] = $row;
    return sjwtBuildUser($GLOBALS['__sjwt_users'][(int) $row['ID']]);
}

function sjwtBuildUser(array $row): WP_User
{
    return new WP_User($row);
}

if (!function_exists('get_user_by')) {
    function get_user_by(string $by, string $value): WP_User|false
    {
        $col = match ($by) {
            'id'     => 'ID',
            'login'  => 'user_login',
            'email'  => 'user_email',
            'slug'   => 'user_nicename',
            default  => null,
        };
        if ($col === null) {
            return false;
        }
        foreach (($GLOBALS['__sjwt_users'] ?? []) as $row) {
            $haystack = $col === 'ID' ? (int) $row['ID'] : (string) $row[$col];
            $needle   = $col === 'ID' ? (int) $value : $value;
            if ($haystack === $needle) {
                return sjwtBuildUser($row);
            }
        }
        return false;
    }
}

if (!function_exists('get_userdata')) {
    function get_userdata(int $userId): WP_User|false
    {
        $row = $GLOBALS['__sjwt_users'][$userId] ?? null;
        return $row === null ? false : sjwtBuildUser($row);
    }
}

/* ─── authentication / password hashing ───────────────────────────────── */

if (!function_exists('wp_hash_password')) {
    function wp_hash_password(string $password): string
    {
        return 'sjwt-hash:' . hash('sha256', $password . wp_salt('auth'));
    }
}

if (!function_exists('wp_check_password')) {
    function wp_check_password(string $password, string $hash, int $userId = 0): bool
    {
        return hash_equals($hash, wp_hash_password($password));
    }
}

if (!function_exists('wp_set_password')) {
    function wp_set_password(string $password, int $userId): void
    {
        $GLOBALS['__sjwt_users'][$userId]['user_pass'] = wp_hash_password($password);
    }
}

if (!function_exists('wp_authenticate')) {
    function wp_authenticate(string $username, string $password): WP_User|WP_Error
    {
        $lookup = str_contains($username, '@')
            ? get_user_by('email', $username)
            : get_user_by('login', $username);

        if (!$lookup) {
            return new WP_Error('invalid_username', sprintf(
                '<strong>Unknown user.</strong> Please check the username and try again. %s',
                $username
            ));
        }
        if (!wp_check_password($password, $lookup->user_pass, $lookup->ID)) {
            return new WP_Error('incorrect_password', sprintf(
                'The password you entered for the username %s is incorrect.',
                $username
            ));
        }
        return $lookup;
    }
}

/* ─── core password-reset key lifecycle (WP 5.7/6.8 semantics, simplified) ── */

if (!function_exists('get_password_reset_key')) {
    function get_password_reset_key(WP_User $user): string|WP_Error
    {
        $key = bin2hex(random_bytes(16));
        $GLOBALS['__sjwt_reset_keys'][$user->user_login] = ['key' => $key, 'created' => time()];
        $GLOBALS['__sjwt_users'][$user->ID]['user_activation_key'] = $key;
        return $key;
    }
}

if (!function_exists('check_password_reset_key')) {
    function check_password_reset_key(string $key, string $login): WP_User|WP_Error
    {
        $user = get_user_by('login', $login);
        if (!$user) {
            return new WP_Error('invalid_key', 'The password reset key is invalid.');
        }
        // The key must still match the user's activation key (burning it via
        // the atomic UPDATE clears this, so reused/already-consumed keys fail).
        $stored = (string) ($GLOBALS['__sjwt_reset_keys'][$login]['key'] ?? '');
        if ($stored === '' || $stored !== $key || $user->user_activation_key !== $key) {
            return new WP_Error('invalid_key', 'The password reset key is invalid.');
        }
        $expiration = (int) apply_filters('password_reset_expiration', DAY_IN_SECONDS);
        $created    = (int) ($GLOBALS['__sjwt_reset_keys'][$login]['created'] ?? 0);
        if ($created + $expiration < time()) {
            return new WP_Error('expired_key', 'The password reset key has expired.');
        }
        return $user;
    }
}

/* ─── mail / URL helpers ──────────────────────────────────────────────── */

if (!function_exists('wp_mail')) {
    function wp_mail(mixed $to, string $subject, string $message, array $headers = [], array $attachments = []): bool
    {
        $args = apply_filters('wp_mail', [
            'to'       => $to,
            'subject'  => $subject,
            'message'  => $message,
            'headers'  => $headers,
        ]);
        if (!empty($args['do_not_send'])) {
            return false;
        }
        $GLOBALS['__sjwt_sent_mail'][] = $args;
        return true;
    }
}

if (!function_exists('network_home_url')) {
    function network_home_url(string $path = ''): string
    {
        $base = $GLOBALS['__sjwt_bloginfo']['url'] ?? 'https://example.test';
        return rtrim($base, '/') . '/' . ltrim($path, '/');
    }
}

if (!function_exists('network_site_url')) {
    function network_site_url(string $path = '', ?string $scheme = null): string
    {
        return network_home_url($path);
    }
}

if (!function_exists('is_multisite')) {
    function is_multisite(): bool
    {
        return false;
    }
}

if (!function_exists('wp_specialchars_decode')) {
    function wp_specialchars_decode(string $string, int $quotes = ENT_NOQUOTES): string
    {
        return htmlspecialchars_decode($string, $quotes);
    }
}

/* ─── actions (do_action mirror of the filter registry) ───────────────── */

if (!function_exists('do_action')) {
    function do_action(string $tag, mixed ...$args): void
    {
        foreach (($GLOBALS['__sjwt_filters'][$tag] ?? []) as $entry) {
            ($entry['cb'])(...array_slice($args, 0, $entry['args']));
        }
    }
}

/* ─── HTTP surface (CORS preflight etc.) ─────────────────────────────── */

if (!function_exists('status_header')) {
    function status_header(int $code): void
    {
        $GLOBALS['__sjwt_status_header'] = $code;
    }
}

if (!function_exists('register_rest_route')) {
    function register_rest_route(string $namespace, string $route, array $args = []): bool
    {
        $GLOBALS['__sjwt_rest_routes'][] = [
            'namespace' => $namespace,
            'route'     => $route,
            'args'      => $args,
        ];
        return true;
    }
}

if (!function_exists('wp_die')) {
    function wp_die(mixed ...$args): void
    {
        $GLOBALS['__sjwt_wp_died'] = true;
    }
}

/* ─── minimal wpdb test double (compare-and-clear SQL flow) ───────────── */

final class SjwtWpdb
{
    public string $users  = 'wp_users';
    public string $prefix = 'wp_';

    public function prepare(string $sql, string|int|float ...$args): string
    {
        $i = 0;
        return (string) preg_replace_callback('/%[dsf]/', function (array $m) use ($args, &$i): string {
            $arg = $args[$i] ?? '';
            $i++;
            return match ($m[0]) {
                '%d' => (string) (int) $arg,
                '%f' => (string) (float) $arg,
                '%s' => "'" . str_replace("\\", "\\\\", (string) $arg) . "'",
            };
        }, $sql);
    }

    public function query(string $sql): int
    {
        // The plugin's only ->query() call: atomic activation-key consume
        // ("UPDATE ... SET user_activation_key = '' WHERE ID = %d AND key = %s").
        if (str_contains($sql, "SET user_activation_key = ''")) {
            if (preg_match('/WHERE ID = ([0-9]+) AND user_activation_key = \'(.*?)\'/', $sql, $m)) {
                $userId = (int) $m[1];
                $key    = $m[2];
                $rows   = $GLOBALS['__sjwt_users'] ?? [];
                if ($key !== '' && ($rows[$userId]['user_activation_key'] ?? '') === $key) {
                    $GLOBALS['__sjwt_users'][$userId]['user_activation_key'] = '';
                    return 1;
                }
            }
        }
        return 0;
    }

    public function update(string $table, array $fields, array $where): int
    {
        if ($table !== $this->users) {
            return 0;
        }
        $userId = (int) ($where['ID'] ?? 0);
        if (!isset($GLOBALS['__sjwt_users'][$userId])) {
            return 0;
        }
        foreach ($fields as $col => $value) {
            $GLOBALS['__sjwt_users'][$userId][$col] = $value;
        }
        return 1;
    }
}

global $wpdb;
if (!($wpdb instanceof SjwtWpdb)) {
    $wpdb = new SjwtWpdb();
}

/* ─── minimal REST classes (guarded against real WP) ──────────────────── */

if (!class_exists('WP_REST_Request')) {
    final class WP_REST_Request
    {
        private array $params;

        public function __construct(array $params = [])
        {
            $this->params = $params;
        }

        public function get_param(string $key): mixed
        {
            return $this->params[$key] ?? null;
        }

        public function get_params(): array
        {
            return $this->params;
        }

        public function has_param(string $key): bool
        {
            return array_key_exists($key, $this->params);
        }

        public function set_param(string $key, mixed $value): void
        {
            $this->params[$key] = $value;
        }
    }
}

if (!class_exists('WP_REST_Response')) {
    final class WP_REST_Response
    {
        private mixed $data;
        private int $status;
        private array $headers;

        public function __construct(mixed $data = null, int $status = 200, array $headers = [])
        {
            $this->data    = $data;
            $this->status  = $status;
            $this->headers = $headers;
        }

        public function get_status(): int
        {
            return $this->status;
        }

        public function get_data(): mixed
        {
            return $this->data;
        }

        public function get_headers(): array
        {
            return $this->headers;
        }

        public function header(string $key, string $value, bool $replace = true): void
        {
            $this->headers[$key] = $value;
        }
    }
}
