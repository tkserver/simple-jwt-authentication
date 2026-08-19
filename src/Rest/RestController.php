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
        add_filter('rest_pre_dispatch', fn($request, $server) => $this->preDispatch($request, $server), 10, 2);
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

        if (str_contains($requestUri, 'token/validate')) {
            return $user;
        }

        $token = $this->tokenService->validateToken(forMiddleware: true);

        if (is_wp_error($token)) {
            if ($token->get_error_code() !== 'jwt_auth_no_auth_header') {
                $this->tokenService->setJwtError($token);
            }
            return $user;
        }

        return (int) $token->data->user->id;
    }

    /**
     * Surface stored JWT errors before the REST server dispatches the request.
     *
     * @param WP_REST_Request $request
     * @param \WP_REST_Server $server
     */
    public function preDispatch(WP_REST_Request $request, \WP_REST_Server $server): WP_REST_Request|\WP_Error
    {
        $jwtError = $this->tokenService->getJwtError();
        if ($jwtError !== null) {
            return $jwtError;
        }
        return $request;
    }
}
