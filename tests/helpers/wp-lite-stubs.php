<?php
/**
 * Minimal, guarded WordPress surface for the pure-PHP suite (tests/Unit).
 *
 * Everything here is guarded (`function_exists` / `class_exists` / `defined`)
 * so that:
 *   - the richer Phase 2 shim (tests/WP/shim-functions.php) can require_once
 *     this file first and safely layer additional functions on top, and
 *   - with processIsolation enabled, unit tests and WP-shim tests never share
 *     a process, so the two layers never conflict at all.
 *
 * State lives in $GLOBALS keys; SjwtTestState::reset() clears it. These stubs
 * mirror ONLY the behavior the production code under test relies on — they
 * are not a WordPress mock.
 */

declare(strict_types=1);

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}
if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}
if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

if (!isset($GLOBALS['__sjwt_options_store'])) {
    $GLOBALS['__sjwt_options_store'] = [];
}
if (!isset($GLOBALS['__sjwt_meta_store'])) {
    $GLOBALS['__sjwt_meta_store'] = [];
}
if (!isset($GLOBALS['__sjwt_transients'])) {
    $GLOBALS['__sjwt_transients'] = [];
}
if (!isset($GLOBALS['__sjwt_filters'])) {
    $GLOBALS['__sjwt_filters'] = [];
}
if (!isset($GLOBALS['__sjwt_bloginfo'])) {
    $GLOBALS['__sjwt_bloginfo'] = ['url' => 'https://example.test'];
}
if (!isset($GLOBALS['__sjwt_salts'])) {
    $GLOBALS['__sjwt_salts'] = [];
}

final class SjwtTestState
{
    public static function reset(): void
    {
        // Clear every '__sjwt_*' store (unit + WP-shim state) in one pass so
        // the shim layer can introduce stores without touching this method.
        foreach (array_keys($GLOBALS) as $key) {
            if (str_starts_with((string) $key, '__sjwt_')) {
                unset($GLOBALS[$key]);
            }
        }

        $GLOBALS['__sjwt_options_store'] = [];
        $GLOBALS['__sjwt_meta_store']    = [];
        $GLOBALS['__sjwt_transients']    = [];
        $GLOBALS['__sjwt_filters']       = [];
        $GLOBALS['__sjwt_salts']         = [];
        $GLOBALS['__sjwt_bloginfo']      = ['url' => 'https://example.test'];
        $GLOBALS['__sjwt_rest_prefix']   = 'wp-json';

        $_SERVER['REMOTE_ADDR']     = '198.51.100.7';
        $_SERVER['HTTP_USER_AGENT'] = 'phpunit-test-agent';
        unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);

        if (class_exists(\SimpleJwtAuth\Config::class)) {
            \SimpleJwtAuth\Config::flushCache();
        }
    }
}

if (!class_exists('WP_Error')) {
    final class WP_Error
    {
        private array $codes    = [];
        private array $messages = [];
        private array $datas    = [];

        public function __construct(string|int $code = '', string $message = '', mixed $data = null)
        {
            if ($code !== '') {
                $this->codes[] = $code;
                $this->messages[$code] = $message;
                if ($data !== null) {
                    $this->datas[$code] = $data;
                }
            }
        }

        public function get_error_code(): string|int
        {
            return $this->codes[0] ?? '';
        }

        public function get_error_codes(): array
        {
            return $this->codes;
        }

        public function get_error_message(string $code = ''): string
        {
            $code = $code !== '' ? $code : (string) ($this->codes[0] ?? '');
            return $this->messages[$code] ?? '';
        }

        public function get_error_messages(string $code = ''): array
        {
            if ($code !== '') {
                return isset($this->messages[$code]) ? [$this->messages[$code]] : [];
            }
            return array_values($this->messages);
        }

        public function get_error_data(mixed $code = ''): mixed
        {
            if ($code !== '' && array_key_exists($code, $this->datas)) {
                return $this->datas[$code];
            }
            return $this->datas === [] ? '' : reset($this->datas);
        }

        public function get_error_data_of(string $code): mixed
        {
            return $this->datas[$code] ?? null;
        }
    }
}

if (!class_exists('WP_User')) {
    final class WP_User
    {
        public int $ID = 0;
        public string $user_login = '';
        public string $user_email = '';
        public string $user_nicename = '';
        public string $display_name = '';
        public string $user_pass = '';
        public string $user_activation_key = '';
        public object $data;

        public function __construct(array $props = [])
        {
            foreach (['ID', 'user_login', 'user_email', 'user_nicename', 'display_name', 'user_pass', 'user_activation_key'] as $key) {
                if (array_key_exists($key, $props)) {
                    $this->{$key} = $props[$key];
                }
            }
            $this->data = (object) [
                'ID'            => $this->ID,
                'user_login'    => $this->user_login,
                'user_email'    => $this->user_email,
                'user_nicename' => $this->user_nicename,
                'display_name'  => $this->display_name,
                'user_pass'     => $this->user_pass,
                'user_activation_key' => $this->user_activation_key,
            ];
        }
    }
}

if (!function_exists('get_option')) {
    function get_option(mixed $name, mixed $default = false): mixed
    {
        $store = $GLOBALS['__sjwt_options_store'] ?? [];
        return array_key_exists($name, $store) ? $store[$name] : $default;
    }
}

if (!function_exists('get_user_meta')) {
    function get_user_meta(int $userId, string $key, bool $single = true): mixed
    {
        $value = ($GLOBALS['__sjwt_meta_store'][$userId][$key] ?? null);
        return $value === null ? '' : $value;
    }
}

if (!function_exists('update_user_meta')) {
    function update_user_meta(int $userId, string $key, mixed $value): bool
    {
        $GLOBALS['__sjwt_meta_store'][$userId][$key] = $value;
        return true;
    }
}

if (!function_exists('delete_user_meta')) {
    function delete_user_meta(int $userId, string $key): bool
    {
        unset($GLOBALS['__sjwt_meta_store'][$userId][$key]);
        return true;
    }
}

if (!function_exists('add_filter')) {
    function add_filter(string $tag, callable $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        $GLOBALS['__sjwt_filters'][$tag][] = ['cb' => $callback, 'args' => $acceptedArgs];
        return true;
    }
}

if (!function_exists('apply_filters')) {
    function apply_filters(string $tag, mixed $value, mixed ...$extra): mixed
    {
        foreach (($GLOBALS['__sjwt_filters'][$tag] ?? []) as $entry) {
            $argv  = array_slice([$value, ...$extra], 0, $entry['args']);
            $value = ($entry['cb'])(...$argv);
        }
        return $value;
    }
}

if (!function_exists('set_transient')) {
    function set_transient(string $key, mixed $value, int $expiration = 0): bool
    {
        $GLOBALS['__sjwt_transients'][$key] = [
            'v' => $value,
            'e' => $expiration > 0 ? time() + $expiration : 0,
        ];
        return true;
    }
}

if (!function_exists('get_transient')) {
    function get_transient(string $key): mixed
    {
        $row = $GLOBALS['__sjwt_transients'][$key] ?? null;
        if ($row === null) {
            return false;
        }
        if ($row['e'] !== 0 && time() >= $row['e']) {
            unset($GLOBALS['__sjwt_transients'][$key]);
            return false;
        }
        return $row['v'];
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient(string $key): bool
    {
        unset($GLOBALS['__sjwt_transients'][$key]);
        return true;
    }
}

if (!function_exists('get_bloginfo')) {
    function get_bloginfo(string $show = ''): string
    {
        $map = $GLOBALS['__sjwt_bloginfo'] ?? [];
        if ($show === '') {
            return (string) ($map['url'] ?? '');
        }
        return (string) ($map[$show] ?? '');
    }
}

if (!function_exists('wp_salt')) {
    function wp_salt(string $scheme = 'auth'): string
    {
        $map = $GLOBALS['__sjwt_salts'] ?? [];
        return (string) ($map[$scheme] ?? 'sjwt-test-salt-' . $scheme);
    }
}

if (!function_exists('wp_generate_uuid4')) {
    function wp_generate_uuid4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string
    {
        return $text;
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error(mixed $thing): bool
    {
        return $thing instanceof WP_Error;
    }
}

/* ─── REST surface (Phase 1.5 middleware / matcher tests) ─────────────── */

if (!isset($GLOBALS['__sjwt_rest_prefix'])) {
    $GLOBALS['__sjwt_rest_prefix'] = 'wp-json';
}

if (!function_exists('add_action')) {
    // WP treats actions as filters with a null value; storing them in the same
    // registry keeps behavior consistent if a later phase adds do_action().
    function add_action(string $tag, callable $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        return add_filter($tag, $callback, $priority, $acceptedArgs);
    }
}

if (!function_exists('rest_get_url_prefix')) {
    function rest_get_url_prefix(): string
    {
        return (string) ($GLOBALS['__sjwt_rest_prefix'] ?? 'wp-json');
    }
}

if (!function_exists('untrailingslashit')) {
    function untrailingslashit(string $value): string
    {
        return rtrim($value, '/\\');
    }
}
