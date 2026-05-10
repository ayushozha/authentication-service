package com.authservice.sdk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class AuthServiceClient {
  private final String baseUrl;
  private final String apiKey;
  private final String adminKey;
  private final HttpClient http = HttpClient.newHttpClient();
  private final ObjectMapper json = new ObjectMapper();
  private String accessToken;
  private String refreshToken;

  public AuthServiceClient(String baseUrl, String apiKey, String adminKey) {
    this.baseUrl = baseUrl.replaceAll("/+$", "");
    this.apiKey = apiKey;
    this.adminKey = adminKey;
  }

  public Map<String, Object> request(String method, String path, Object body, boolean admin, boolean auth) throws Exception {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
    builder.header("Content-Type", "application/json");
    if (admin && adminKey != null) builder.header("X-Admin-Key", adminKey);
    else if (apiKey != null) builder.header("X-API-Key", apiKey);
    if (auth && accessToken != null) builder.header("Authorization", "Bearer " + accessToken);
    HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() >= 400) throw new RuntimeException("AuthService " + response.statusCode() + ": " + response.body());
    if (response.body() == null || response.body().isBlank()) return Map.of();
    return json.readValue(response.body(), new TypeReference<Map<String, Object>>() {});
  }

  public Map<String, Object> login(String email, String password) throws Exception {
    Map<String, Object> body = new HashMap<>();
    body.put("email", email);
    body.put("password", password);
    body.put("session_mode", "token");
    Map<String, Object> out = request("POST", "/api/auth/login", body, false, false);
    accessToken = (String) out.get("access_token");
    refreshToken = (String) out.get("refresh_token");
    return out;
  }

  public Map<String, Object> me() throws Exception { return request("GET", "/api/auth/me", null, false, true); }
  public Map<String, Object> createClient(Map<String, Object> body) throws Exception { return request("POST", "/api/admin/clients", body, true, false); }
  public Map<String, Object> createServiceAccount(String clientId, Map<String, Object> body) throws Exception { return request("POST", "/api/admin/clients/" + clientId + "/service-accounts", body, true, false); }
  public String getAccessToken() { return accessToken; }
  public String getRefreshToken() { return refreshToken; }
}
