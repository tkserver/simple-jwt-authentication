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
    private string $namespace;
    private TokenService $tokenService;
    private TokenEndpoint $endpoint;

    public function __construct(string $namespace, TokenService $tokenService, TokenEndpoint $endpoint)
    {
        $this->namespace    = $namespace;
        $this->tokenService = $tokenService;
        $this->endpoint     = $endpoint;

        add_action('rest_api_init', fn() => $this->registerRoutes());
        add_action('rest_api_init', fn() => $this->addCorsSupport());
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
    }

    private function addCorsSupport(): void
    {
        if (!Config::isCorsEnabled()) {
            return;
        }

        $headers = apply_filters('jwt_auth_cors_allow_headers', 'Access-Control-Allow-Headers, Content-Type, Authorization');
        header(sprintf('Access-Control-Allow-Headers: %s', $headers));
    }

    /**
     * Middleware: attempt JWT authentication on REST API requests.
     *
     * @param int|false $user
     * @return int|false
     */
    public function determineCurrentUser(int|false $user): int|false
    {
        $restPrefix = rest_get_url_prefix();
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';

        if (!str_contains($requestUri, $restPrefix)) {
            return $user;
        }

        // Skip our own endpoints that use username/password instead of Bearer.
        $tokenGeneratePath = $this->namespace . '/token';
        $tokenResetPath    = $this->namespace . '/token/resetpassword';
        $tokenValidatePath = $this->namespace . '/token/validate';

        if (
            preg_match('#' . preg_quote($tokenGeneratePath, '#') . '(\?.*)?$#', $requestUri)
            || str_contains($requestUri, $tokenValidatePath)
            || str_contains($requestUri, $tokenResetPath)
        ) {
            return $user;
        }

        // If no Authorization header at all, user isn't trying to use JWT.
        if ($this->getAuthHeader() === null) {
            return $user;
        }

        $token = $this->tokenService->validateToken(forMiddleware: true);

        if (is_wp_error($token)) {
            $this->tokenService->setJwtError($token);
            return $user;
        }

        return (int) $token->data->user->id;
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
     * @param mixed $pre The pre-dispatch value (null by default).
     */
    public function preDispatch(mixed $pre): mixed
    {
        $jwtError = $this->tokenService->getJwtError();
        if ($jwtError !== null) {
            return $jwtError;
        }
        return $pre;
    }
}
