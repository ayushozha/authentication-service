<?php
namespace AuthService;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JwtVerifier {
    public function __construct(private string $jwksUrl, private ?string $clientId = null, private ?string $tokenUse = null) {}

    public function verify(string $token, array $requiredScopes = [], array $requiredOrgPermissions = []): object {
        $jwks = json_decode(file_get_contents($this->jwksUrl), true);
        $claims = JWT::decode($token, JWK::parseKeySet($jwks));
        if ($this->clientId && ($claims->client_id ?? null) !== $this->clientId) throw new \RuntimeException("token client mismatch");
        if ($this->tokenUse && ($claims->token_use ?? null) !== $this->tokenUse) throw new \RuntimeException("token_use mismatch");
        $scopes = isset($claims->scopes) ? $claims->scopes : preg_split('/\s+/', $claims->scope ?? "", -1, PREG_SPLIT_NO_EMPTY);
        foreach ($requiredScopes as $scope) if (!in_array($scope, $scopes, true)) throw new \RuntimeException("missing scope ".$scope);
        $perms = $claims->org_permissions ?? [];
        foreach ($requiredOrgPermissions as $permission) if (($claims->org_role ?? "") !== "owner" && !in_array($permission, $perms, true)) throw new \RuntimeException("missing organization permission ".$permission);
        return $claims;
    }

    public static function verifyWebhookSignature(string $secret, string $timestamp, string $signature, string $body): bool {
        $expected = "v1=".hash_hmac("sha256", $timestamp.".".$body, $secret);
        return hash_equals($expected, $signature);
    }
}
