package com.sam.keystone.infrastructure.jwt

import com.auth0.jwt.exceptions.JWTVerificationException
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

@Component
class JWTTokenGeneratorService(private val generator: JWTKeysGenerator) {

    @Value($$"${jwt.access-token-expiry-minutes}")
    lateinit var accessTokenLife: String

    @Value($$"${jwt.refresh-token-expiry-days}")
    lateinit var refreshTokenLife: String

    fun generateTokenPairs(
        user: User,
        createRefreshToken: Boolean = true,
        accessTokenExpiry: Duration? = null,
        refreshTokenExpiry: Duration? = null,
    ): TokenResponseDto {

        val accessTokenDuration = accessTokenExpiry ?: (accessTokenLife).toInt().minutes
        val refreshTokenDuration = refreshTokenExpiry ?: (refreshTokenLife).toInt().days

        val accessToken = generator.generateToken(
            timeToLive = accessTokenDuration,
            claims = prepareClaims(user, JWTTokenType.ACCESS_TOKEN)
        )
        val refreshToken = if (createRefreshToken) generator.generateToken(
            timeToLive = refreshTokenDuration,
            claims = prepareClaims(user, JWTTokenType.REFRESH_TOKEN)
        ) else null

        return TokenResponseDto(
            accessToken = accessToken,
            refreshToken = refreshToken
        )
    }

    @OptIn(ExperimentalTime::class)
    fun validateToken(token: String, type: JWTTokenType = JWTTokenType.ACCESS_TOKEN): Pair<Long, Duration>? {
        return try {
            val result = generator.validateToken(token)
            if (result.isExpired) return null

            val userId = result.claims.getOrDefault(JWT_CLAIM_USER_ID, null)?.asLong() ?: -1
            val tokenTYpe = result.claims.getOrDefault(JWT_CLAIM_TOKEN_TYPE, null)

            if (tokenTYpe?.asString() == type.name) userId to result.tokenTTL else null
        } catch (_: JWTVerificationException) {
            null
        }
    }

    private fun prepareClaims(user: User, tokenType: JWTTokenType) = mapOf(
        JWT_CLAIM_USER_NAME to user.userName,
        JWT_CLAIM_USER_ID to user.id,
        JWT_CLAIM_TOKEN_TYPE to tokenType.name
    )

    companion object {
        private const val JWT_CLAIM_USER_NAME = "user_name"
        private const val JWT_CLAIM_USER_ID = "user_id"
        private const val JWT_CLAIM_TOKEN_TYPE = "token_type"
    }
}