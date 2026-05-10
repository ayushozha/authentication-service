<?php
namespace AuthService\Laravel;

use AuthService\JwtVerifier;
use Closure;

class AuthServiceMiddleware {
    public function __construct(private JwtVerifier $verifier) {}

    public function handle($request, Closure $next) {
        $header = $request->header("Authorization", "");
        $token = stripos($header, "Bearer ") === 0 ? substr($header, 7) : "";
        $request->attributes->set("authservice", $this->verifier->verify($token));
        return $next($request);
    }
}
