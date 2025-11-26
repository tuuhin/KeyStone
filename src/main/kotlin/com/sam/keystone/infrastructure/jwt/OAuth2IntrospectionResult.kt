package com.sam.keystone.infrastructure.jwt

import com.sam.keystone.modules.user.models.JWTTokenType
import java.time.Instant

data class OAuth2IntrospectionResult(
    val active: Boolean,
    val clientId: String, val userId: Long,
    val scope: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val tokenType: JWTTokenType = JWTTokenType.ACCESS_TOKEN,
)