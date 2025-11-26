package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty
import com.sam.keystone.modules.user.models.JWTTokenType
import java.time.Instant

data class OAuth2TokenIntrospectResponseDto(
    @field:JsonProperty("is_active") val active: Boolean,
    @field:JsonProperty("client_id") val clientId: String,
    @field:JsonProperty("user_id") val userId: Long,
    @field:JsonProperty("scopes") val scope: String,
    @field:JsonProperty("issued_at") val issuedAt: Instant,
    @field:JsonProperty("expires_at") val expiresAt: Instant,
    @field:JsonProperty("token_type") val tokenType: JWTTokenType = JWTTokenType.ACCESS_TOKEN,
)