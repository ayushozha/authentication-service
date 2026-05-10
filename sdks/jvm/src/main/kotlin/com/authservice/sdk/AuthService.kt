package com.authservice.sdk

fun authServiceClient(baseUrl: String, apiKey: String? = null, adminKey: String? = null): AuthServiceClient =
    AuthServiceClient(baseUrl, apiKey, adminKey)
