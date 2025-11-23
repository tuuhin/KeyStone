package com.sam.keystone.infrastructure.jwt

import com.auth0.jwt.interfaces.Claim
import java.time.Instant
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

data class JWTValidationResult(
    val claims: Map<String, Claim> = emptyMap(),
    val tokenExpiryInstant: Instant = Instant.now(),
    val tokenCreateInstant: Instant = Instant.now(),
) {

    @OptIn(ExperimentalTime::class)
    val tokenTTL: Duration
        get() = (tokenExpiryInstant.toKotlinInstant() - Clock.System.now())

    val isExpired: Boolean
        get() = tokenTTL.isNegative()
}
