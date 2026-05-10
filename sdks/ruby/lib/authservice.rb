require "faraday"
require "json"
require_relative "authservice/jwt_verifier"
require_relative "authservice/rails_middleware"

module AuthService
  class Client
    attr_reader :access_token, :refresh_token

    def initialize(base_url:, api_key: nil, admin_key: nil)
      @base_url = base_url.sub(%r{/+$}, "")
      @api_key = api_key
      @admin_key = admin_key
      @http = Faraday.new(url: @base_url)
    end

    def request(method, path, body: nil, admin: false, auth: true)
      response = @http.public_send(method.downcase, path) do |req|
        req.headers["X-Admin-Key"] = @admin_key if admin && @admin_key
        req.headers["X-API-Key"] = @api_key if !admin && @api_key
        req.headers["Authorization"] = "Bearer #{@access_token}" if auth && @access_token
        req.headers["Content-Type"] = "application/json" if body
        req.body = JSON.generate(body) if body
      end
      raise "AuthService #{response.status}: #{response.body}" if response.status >= 400
      response.body.to_s.empty? ? {} : JSON.parse(response.body)
    end

    def login(email:, password:)
      payload = request("POST", "/api/auth/login", body: {email: email, password: password, session_mode: "token"}, auth: false)
      @access_token = payload["access_token"]
      @refresh_token = payload["refresh_token"]
      payload
    end

    def me
      request("GET", "/api/auth/me")
    end

    def create_client(body)
      request("POST", "/api/admin/clients", body: body, admin: true, auth: false)
    end

    def create_service_account(client_id, body)
      request("POST", "/api/admin/clients/#{client_id}/service-accounts", body: body, admin: true, auth: false)
    end
  end
end
