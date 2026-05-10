<?php
namespace AuthService;

use GuzzleHttp\Client;

class AuthServiceClient {
    private Client $http;
    private ?string $apiKey;
    private ?string $adminKey;
    public ?string $accessToken = null;
    public ?string $refreshToken = null;

    public function __construct(string $baseUrl, ?string $apiKey = null, ?string $adminKey = null) {
        $this->http = new Client(["base_uri" => rtrim($baseUrl, "/")]);
        $this->apiKey = $apiKey;
        $this->adminKey = $adminKey;
    }

    public function request(string $method, string $path, ?array $body = null, bool $admin = false, bool $auth = true): array {
        $headers = [];
        if ($admin && $this->adminKey) $headers["X-Admin-Key"] = $this->adminKey;
        elseif ($this->apiKey) $headers["X-API-Key"] = $this->apiKey;
        if ($auth && $this->accessToken) $headers["Authorization"] = "Bearer ".$this->accessToken;
        $options = ["headers" => $headers];
        if ($body !== null) $options["json"] = $body;
        $response = $this->http->request($method, $path, $options);
        $payload = json_decode((string)$response->getBody(), true) ?: [];
        return $payload;
    }

    public function login(string $email, string $password): array {
        $payload = $this->request("POST", "/api/auth/login", ["email" => $email, "password" => $password, "session_mode" => "token"], false, false);
        $this->accessToken = $payload["access_token"] ?? null;
        $this->refreshToken = $payload["refresh_token"] ?? null;
        return $payload;
    }

    public function me(): array { return $this->request("GET", "/api/auth/me"); }
    public function createClient(array $body): array { return $this->request("POST", "/api/admin/clients", $body, true, false); }
    public function createServiceAccount(string $clientId, array $body): array { return $this->request("POST", "/api/admin/clients/".$clientId."/service-accounts", $body, true, false); }
}
