package com.authservice.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
}
