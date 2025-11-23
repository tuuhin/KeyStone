package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class OAuth2TokenResponseDto(
    @field:JsonProperty("access_token") val accessToken: String,
    @field:JsonProperty("token_type") val tokenType: String = "Bearer",
    @field:JsonProperty("expires_in") val expiry: Long = 0L,
    @field:JsonProperty("refresh_token") val refreshToken: String? = null,
    @field:JsonProperty("refresh_token_expiry") val refreshTokenExpiry: Long = 0L,
    @field:JsonProperty("redirect_uri") val redirectURI: String? = null,
    @field:JsonProperty("scopes") val scopes: String? = null,
    @field:JsonProperty("created_at") val createdAt: Instant = Instant.now(),
    @field:JsonProperty("state") val state: String = "",
)
