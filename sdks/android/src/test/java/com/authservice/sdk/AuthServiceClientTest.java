package com.authservice.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AuthServiceClientTest {
    @Test
    void memoryTokenStorePersistsTokens() {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();

        store.setAccessToken("access");
        store.setRefreshToken("refresh");

        assertEquals("access", store.getAccessToken());
        assertEquals("refresh", store.getRefreshToken());
    }

    @Test
    void clearSessionClearsTokenStore() {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();
        store.setAccessToken("access");
        store.setRefreshToken("refresh");
        AuthServiceClient client = new AuthServiceClient("https://auth.example.com/", "api-key", "token", store);

        client.clearSession();

        assertNull(store.getAccessToken());
        assertNull(store.getRefreshToken());
    }

    @Test
    void responseErrorPrefersServerErrorField() {
        AuthServiceClient.AuthServiceResponse response = new AuthServiceClient.AuthServiceResponse(
                401,
                "{\"error\":\"Invalid email or password.\"}"
        );

        assertEquals("Invalid email or password.", response.getError());
    }

    @Test
    void responseErrorUsesServerMessageField() {
        AuthServiceClient.AuthServiceResponse response = new AuthServiceClient.AuthServiceResponse(
                401,
                "{\"message\":\"API key is missing or invalid.\"}"
        );

        assertEquals("API key is missing or invalid.", response.getError());
    }

    @Test
    void responseExposesCanonicalAuthErrorFields() {
        AuthServiceClient.AuthServiceResponse response = new AuthServiceClient.AuthServiceResponse(
                429,
                "{\"error\":\"too many requests\",\"code\":\"rate_limited\",\"auth_code\":\"AUTH_RATE_LIMITED\",\"user_message\":\"Too many attempts. Try again in a few minutes.\",\"retryable\":true}"
        );

        assertEquals("AUTH_RATE_LIMITED", response.getAuthCode());
        assertEquals("Too many attempts. Try again in a few minutes.", response.getUserMessage());
        assertTrue(response.isRetryable());
    }

    @Test
    void responseErrorFallsBackToBody() {
        AuthServiceClient.AuthServiceResponse response = new AuthServiceClient.AuthServiceResponse(
                500,
                "upstream failed"
        );

        assertEquals("upstream failed", response.getError());
    }

    @Test
    void responseExposesTwoFactorChallengeFields() {
        AuthServiceClient.AuthServiceResponse response = new AuthServiceClient.AuthServiceResponse(
                200,
                "{\"requires_2fa\":true,\"two_factor_token\":\"challenge-token\"}"
        );

        assertTrue(response.requires2FA());
        assertEquals("challenge-token", response.getTwoFactorToken());
    }

    @Test
    void loginRequestsJsonTokenTransportAndPersistsTokens() throws Exception {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();
        AtomicReference<String> requestPath = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        HttpServer server = startJsonServer(
                200,
                "{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"refresh\":{\"transport\":\"json\",\"expires_in\":604800}}",
                exchange -> {
                    requestPath.set(exchange.getRequestURI().toString());
                    requestBody.set(readAll(exchange.getRequestBody()));
                }
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key", "token", store);

            client.login("user@example.com", "Password123!");

            assertEquals("/api/auth/login", requestPath.get());
            assertTrue(requestBody.get().contains("\"session_mode\":\"token\""));
            assertTrue(requestBody.get().contains("\"token_transport\":\"json\""));
            assertEquals("access", store.getAccessToken());
            assertEquals("refresh", store.getRefreshToken());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void requestExceptionUsesCanonicalAuthErrorFields() throws Exception {
        HttpServer server = startJsonServer(
                401,
                "{\"error\":\"Invalid email or password.\",\"code\":\"invalid_credentials\",\"auth_code\":\"AUTH_INVALID_CREDENTIALS\",\"user_message\":\"Invalid email or password.\",\"retryable\":false}",
                exchange -> {}
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key");

            try {
                client.login("user@example.com", "wrong");
            } catch (AuthServiceClient.AuthServiceException err) {
                assertEquals(401, err.getStatusCode());
                assertEquals("AUTH_INVALID_CREDENTIALS", err.getAuthCode());
                assertEquals("Invalid email or password.", err.getMessage());
                assertTrue(!err.isRetryable());
                return;
            }
            throw new AssertionError("Expected login to throw");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void verifyEmailSendsToken() throws Exception {
        AtomicReference<String> requestPath = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        HttpServer server = startJsonServer(
                200,
                "{\"ok\":\"true\"}",
                exchange -> {
                    requestPath.set(exchange.getRequestURI().toString());
                    requestBody.set(readAll(exchange.getRequestBody()));
                }
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key");

            client.verifyEmail("verify-token");

            assertEquals("/api/auth/verify-email", requestPath.get());
            assertEquals("{\"token\":\"verify-token\"}", requestBody.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void resendVerificationUsesBearerSession() throws Exception {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();
        store.setAccessToken("access");
        AtomicReference<String> requestPath = new AtomicReference<>();
        AtomicReference<String> authorization = new AtomicReference<>();
        HttpServer server = startJsonServer(
                200,
                "{\"ok\":\"true\"}",
                exchange -> {
                    requestPath.set(exchange.getRequestURI().toString());
                    authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
                }
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key", "token", store);

            client.resendVerification();

            assertEquals("/api/auth/resend-verification", requestPath.get());
            assertEquals("Bearer access", authorization.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void verifyTOTPSendsChallengeAndPersistsTokens() throws Exception {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();
        AtomicReference<String> requestPath = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        HttpServer server = startJsonServer(
                200,
                "{\"access_token\":\"mfa-access\",\"refresh_token\":\"mfa-refresh\"}",
                exchange -> {
                    requestPath.set(exchange.getRequestURI().toString());
                    requestBody.set(readAll(exchange.getRequestBody()));
                }
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key", "token", store);

            AuthServiceClient.AuthServiceResponse response = client.verifyTOTP("challenge", "123456", true, "Pixel");

            assertEquals("/api/auth/totp/verify", requestPath.get());
            assertTrue(requestBody.get().contains("\"two_factor_token\":\"challenge\""));
            assertTrue(requestBody.get().contains("\"token_transport\":\"json\""));
            assertTrue(requestBody.get().contains("\"remember_device\":true"));
            assertEquals("mfa-access", response.getAccessToken());
            assertEquals("mfa-access", store.getAccessToken());
            assertEquals("mfa-refresh", store.getRefreshToken());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void finishPasskeyLoginSendsRawCredentialAndPersistsTokens() throws Exception {
        AuthServiceClient.MemoryTokenStore store = new AuthServiceClient.MemoryTokenStore();
        AtomicReference<String> requestPath = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        HttpServer server = startJsonServer(
                200,
                "{\"access_token\":\"passkey-access\",\"refresh_token\":\"passkey-refresh\"}",
                exchange -> {
                    requestPath.set(exchange.getRequestURI().toString());
                    requestBody.set(readAll(exchange.getRequestBody()));
                }
        );

        try {
            AuthServiceClient client = new AuthServiceClient(baseUrl(server), "api-key", "token", store);

            client.finishPasskeyLogin("session 1", "{\"id\":\"credential\"}");

            assertEquals("/api/auth/passkey/login/finish?session_id=session+1&session_mode=token&token_transport=json", requestPath.get());
            assertEquals("{\"id\":\"credential\"}", requestBody.get());
            assertEquals("passkey-access", store.getAccessToken());
            assertEquals("passkey-refresh", store.getRefreshToken());
        } finally {
            server.stop(0);
        }
    }

    private static HttpServer startJsonServer(int statusCode, String responseBody, ExchangeProbe probe) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            probe.handle(exchange);
            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        return server;
    }

    private static String baseUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static String readAll(InputStream stream) throws IOException {
        byte[] bytes = stream.readAllBytes();
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private interface ExchangeProbe {
        void handle(HttpExchange exchange) throws IOException;
    }
}
