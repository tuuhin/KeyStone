package com.sam.keystone.infrastructure.jwt

import com.auth0.jwt.interfaces.Claim
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class JWTValidationResult(
    val claims: Map<String, Claim> = emptyMap(),
    val tokenTTL: Duration = 0.seconds,
)
