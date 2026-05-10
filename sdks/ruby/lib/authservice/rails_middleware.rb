module AuthService
  class RailsMiddleware
    def initialize(app, verifier)
      @app = app
      @verifier = verifier
    end

    def call(env)
      header = env["HTTP_AUTHORIZATION"].to_s
      token = header.start_with?("Bearer ") ? header[7..] : ""
      env["authservice.claims"] = @verifier.verify(token)
      @app.call(env)
    rescue => e
      [401, {"Content-Type" => "application/json"}, [{error: e.message}.to_json]]
    end
  end
end
