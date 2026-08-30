<?php

declare(strict_types=1);

namespace SimpleJwtAuth\Rest;

use SimpleJwtAuth\Config;
use SimpleJwtAuth\TokenService;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Registers REST routes and handles the auth middleware.
 */
final class RestController
{
    private const CORS_MAX_AGE = 86400;

    private readonly string $namespace;
    private readonly TokenService $tokenService;
    private readonly TokenEndpoint $endpoint;

    /**
     * Guards against re-entry into determine_current_user while validating a JWT.
     * Nested wp_get_current_user() calls (e.g. via __()/locale) must not recurse.
     */
    private bool $determiningUser = false;

    public function __construct(string $namespace, TokenService $tokenService, TokenEndpoint $endpoint)
    {
        $this->namespace    = $namespace;
        $this->tokenService = $tokenService;
        $this->endpoint     = $endpoint;

        add_action('rest_api_init', fn() => $this->registerRoutes());
        add_action('rest_api_init', fn() => $this->addCorsSupport());
        add_action('init', fn() => $this->handleCorsPreflight());
        add_filter('determine_current_user', fn($user) => $this->determineCurrentUser($user), 10);
        add_filter('rest_pre_dispatch', fn($pre) => $this->preDispatch($pre), 10);
    }

    private function registerRoutes(): void
    {
        register_rest_route($this->namespace, '/token', [
            'methods'  => 'POST',
            'callback' => fn(WP_REST_Request $request) => $this->endpoint->generateToken($request),
            'args'     => [
                'username' => ['required' => true, 'type' => 'string'],
                'password' => ['required' => true, 'type' => 'string'],
            ],
        ]);

        register_rest_route($this->namespace, '/token/validate', [
            'methods'  => 'POST',
            'callback' => fn(WP_REST_Request $request) => $this->endpoint->validateToken($request),
        ]);

        register_rest_route($this->namespace, '/token/revoke', [
            'methods'  => 'POST',
            'callback' => fn(WP_REST_Request $request) => $this->endpoint->revokeToken($request),
        ]);

        register_rest_route($this->namespace, '/token/resetpassword', [
            'methods'  => 'POST',
            'callback' => fn(WP_REST_Request $request) => $this->endpoint->resetPassword($request),
            'args'     => [
                'username' => ['required' => true, 'type' => 'string'],
            ],
        ]);

        register_rest_route($this->namespace, '/token/resetpassword/complete', [
            'methods'  => 'POST',
            'callback' => fn(WP_REST_Request $request) => $this->endpoint->completeResetPassword($request),
            'args'     => [
                'key'          => ['required' => true, 'type' => 'string'],
                'login'        => ['required' => true, 'type' => 'string'],
                'new_password' => ['required' => true, 'type' => 'string'],
            ],
        ]);
    }

    private function addCorsSupport(): void
    {
        if (!Config::isCorsEnabled()) {
            return;
        }

        // Scoped to this plugin's own namespace so other plugins' REST
        // routes on the same site don't inherit these headers.
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        if (!str_contains($requestUri, '/' . $this->namespace)) {
            return;
        }

        $headers = apply_filters('jwt_auth_cors_allow_headers', 'Content-Type, Authorization');
        header(sprintf('Access-Control-Allow-Headers: %s', $headers));

        $origin = apply_filters('jwt_auth_cors_allow_origin', '*');
        header(sprintf('Access-Control-Allow-Origin: %s', $origin));
    }

    /**
     * Answer CORS preflight (OPTIONS) requests against the REST API and stop.
     *
     * Runs on `init` so the response is sent before WP routing; non-REST
     * OPTIONS requests fall through untouched.
     */
    public function handleCorsPreflight(): void
    {
        if (!Config::isCorsEnabled()) {
            return;
        }

        if (strtoupper($_SERVER['REQUEST_METHOD'] ?? '') !== 'OPTIONS') {
            return;
        }

        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        if (!str_contains($requestUri, '/' . $this->namespace)) {
            return;
        }

        $headers = apply_filters('jwt_auth_cors_allow_headers', 'Content-Type, Authorization');
        $origin  = apply_filters('jwt_auth_cors_allow_origin', '*');

        status_header(204);
        header(sprintf('Access-Control-Allow-Origin: %s', $origin));
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header(sprintf('Access-Control-Allow-Headers: %s', $headers));
        header(sprintf('Access-Control-Max-Age: %d', self::CORS_MAX_AGE));
        wp_die();
    }

    /**
     * Middleware: attempt JWT authentication on REST API requests.
     *
     * @param int|false $user
     * @return int|false
     */
    public function determineCurrentUser(int|false $user): int|false
    {
        // Already inside validateToken for this request — never re-enter.
        // Without this, anything that touches current-user state (locale via
        // __(), capability checks, etc.) infinite-loops until OOM.
        if ($this->determiningUser) {
            return $user;
        }

        $requestUri = $_SERVER['REQUEST_URI'] ?? '';

        // REST request = pretty `/wp-json/...` OR non-pretty `?rest_route=/...`.
        // Checking only the pretty prefix misses index.php?rest_route= URLs and
        // silently drops Bearer auth (rest_not_logged_in) on those installs.
        if (!$this->isRestRequest($requestUri)) {
            return $user;
        }

        // Skip endpoints that never use Bearer auth (and token/validate, which
        // authenticates itself via its callback to avoid double validation).
        if ($this->isBypassRoute($requestUri)) {
            return $user;
        }

        // If no Authorization header at all, user isn't trying to use JWT.
        // Leave any earlier cookie/app-password user in place.
        if ($this->getAuthHeader() === null) {
            return $user;
        }

        $this->determiningUser = true;
        try {
            $token = $this->tokenService->validateToken(forMiddleware: true);
        } finally {
            $this->determiningUser = false;
        }

        if (is_wp_error($token)) {
            $this->tokenService->setJwtError($token);
            return $user;
        }

        // Valid Bearer takes precedence over a cookie user when both are present.
        return (int) $token->data->user->id;
    }

    /**
     * Whether the current REQUEST_URI targets the REST API.
     */
    private function isRestRequest(string $requestUri): bool
    {
        $restPrefix = rest_get_url_prefix();
        if ($restPrefix !== '' && str_contains($requestUri, $restPrefix)) {
            return true;
        }

        // Non-pretty permalinks: /index.php?rest_route=/wp/v2/...
        $query = (string) parse_url($requestUri, PHP_URL_QUERY);
        if ($query === '') {
            return false;
        }

        parse_str($query, $params);
        return !empty($params['rest_route']) && is_string($params['rest_route']);
    }

    /**
     * Exact path-suffix match for endpoints that must not run JWT middleware.
     *
     * - /token, /token/resetpassword, /token/resetpassword/complete: username/password
     *   (or reset key) auth — never Bearer.
     * - /token/validate: validates the Bearer itself in the callback; running middleware
     *   first would double-decode and is a common double-call hazard.
     *
     * Handles both pretty permalinks (`/wp-json/.../token`) and the
     * `?rest_route=/.../token` form (index.php / non-pretty permalinks).
     */
    private function isBypassRoute(string $requestUri): bool
    {
        $restPath = $this->extractRestPath($requestUri);
        if ($restPath === null) {
            return false;
        }

        $base = '/' . $this->namespace . '/token';

        return $restPath === $base
            || $restPath === $base . '/validate'
            || $restPath === $base . '/resetpassword'
            || $restPath === $base . '/resetpassword/complete';
    }

    /**
     * Normalize the REST route path from REQUEST_URI.
     *
     * @return string|null Path like `/simple-jwt-authentication/v1/token`, or null if not a REST request.
     */
    private function extractRestPath(string $requestUri): ?string
    {
        $path  = (string) parse_url($requestUri, PHP_URL_PATH);
        $query = (string) parse_url($requestUri, PHP_URL_QUERY);

        // Non-pretty: /index.php?rest_route=/ns/v1/token
        if ($query !== '') {
            parse_str($query, $params);
            if (!empty($params['rest_route']) && is_string($params['rest_route'])) {
                return untrailingslashit('/' . ltrim($params['rest_route'], '/'));
            }
        }

        $restPrefix = '/' . trim(rest_get_url_prefix(), '/');
        $pos        = strpos($path, $restPrefix . '/');
        if ($pos === false) {
            // Exact prefix with nothing after (rare) — not a route we care about.
            return null;
        }

        $restPath = substr($path, $pos + strlen($restPrefix));
        return untrailingslashit($restPath === '' ? '/' : $restPath);
    }

    private function getAuthHeader(): ?string
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (empty($auth)) {
            $auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        }
        return $auth !== '' ? $auth : null;
    }

    /**
     * Surface stored JWT errors before the REST server dispatches the request.
     *
     * Translation happens here (request already past determine_current_user),
     * not inside TokenService::validateToken().
     *
     * @param mixed $pre The pre-dispatch value (null by default).
     */
    public function preDispatch(mixed $pre): mixed
    {
        $jwtError = $this->tokenService->getJwtError();
        if ($jwtError === null) {
            return $pre;
        }

        return $this->translateJwtError($jwtError);
    }

    /**
     * Localize JWT error strings that were intentionally left untranslated
     * during determine_current_user to avoid locale/user recursion.
     */
    private function translateJwtError(\WP_Error $error): \WP_Error
    {
        $code = $error->get_error_code();
        $data = $error->get_error_data();

        $message = match ($code) {
            'jwt_auth_no_auth_header' => __('Authorization header not found.', 'simple-jwt-authentication'),
            'jwt_auth_bad_auth_header' => __('Authorization header malformed.', 'simple-jwt-authentication'),
            'jwt_auth_bad_config' => __('JWT is not configured properly. The key is missing.', 'simple-jwt-authentication'),
            'jwt_auth_bad_iss' => __('The issuer does not match this server.', 'simple-jwt-authentication'),
            'jwt_auth_bad_request' => __('User ID not found in the token.', 'simple-jwt-authentication'),
            'jwt_auth_token_revoked' => __('Token has been revoked.', 'simple-jwt-authentication'),
            default => $error->get_error_message(),
        };

        return new \WP_Error($code, $message, $data);
    }
}
