require "jwt"
require "net/http"
require "json"
require "openssl"

module AuthService
  class JwtVerifier
    def initialize(jwks_url:, client_id: nil, token_use: nil)
      @jwks_url = URI(jwks_url)
      @client_id = client_id
      @token_use = token_use
    end

    def verify(token, required_scopes: [], required_org_permissions: [])
      jwks = JSON.parse(Net::HTTP.get(@jwks_url))
      claims, = JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: jwks)
      raise "token client mismatch" if @client_id && claims["client_id"] != @client_id
      raise "token_use mismatch" if @token_use && claims["token_use"] != @token_use
      scopes = claims["scopes"] || claims.fetch("scope", "").split
      required_scopes.each { |scope| raise "missing scope #{scope}" unless scopes.include?(scope) }
      perms = claims["org_permissions"] || []
      required_org_permissions.each { |perm| raise "missing organization permission #{perm}" unless claims["org_role"] == "owner" || perms.include?(perm) }
      claims
    end

    def self.verify_webhook_signature(secret, timestamp, signature, body)
      expected = "v1=" + OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{body}")
      Rack::Utils.secure_compare(expected, signature)
    end
  end
end
