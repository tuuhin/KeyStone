package com.sam.keystone.infrastructure.jwt

import com.sam.keystone.modules.user.models.JWTTokenType
import java.time.Instant
import kotlin.time.Duration

data class JWTAuthResult(
    val userId: Long = -1L,
    val tokenType: JWTTokenType? = null,
    val tokenVersion: Int? = null,
    val issuedAt: Instant,
    val expiresAfter: Duration,
)
