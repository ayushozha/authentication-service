<?php
namespace AuthService\Laravel;

use AuthService\AuthServiceClient;
use AuthService\JwtVerifier;
use Illuminate\Support\ServiceProvider;

class AuthServiceServiceProvider extends ServiceProvider {
    public function register(): void {
        $this->app->singleton(AuthServiceClient::class, fn() => new AuthServiceClient(config("authservice.base_url"), config("authservice.api_key"), config("authservice.admin_key")));
        $this->app->singleton(JwtVerifier::class, fn() => new JwtVerifier(config("authservice.jwks_url"), config("authservice.client_id")));
    }
}
