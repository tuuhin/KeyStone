package com.sam.keystone.infrastructure.jwt

import com.auth0.jwt.exceptions.JWTVerificationException
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

@Component
class JWTTokenGeneratorService(
    private val generator: JWTKeysGenerator,
    private val properties: JWTProperties,
) {

    fun generateTokenPairs(
        user: User,
        createRefreshToken: Boolean = true,
        accessTokenExpiry: Duration? = null,
        refreshTokenExpiry: Duration? = null,
    ): TokenResponseDto {

        val accessTokenLife = properties.accessTokenExpiryMinutes
        val refreshTokenLife = properties.refreshTokenExpiryDays

        val accessTokenDuration = accessTokenExpiry ?: (accessTokenLife).minutes
        val refreshTokenDuration = refreshTokenExpiry ?: (refreshTokenLife).days

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
            refreshToken = refreshToken,
            accessTokenExpireIn = accessTokenDuration,
            refreshTokenExpireIn = refreshTokenDuration
        )
    }

    fun validateAndReturnAuthResult(token: String): JWTAuthResult? {
        return try {
            val result = generator.validateToken(token)
            if (result.isExpired) return null

            val userId = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_USER_ID, null)?.asLong() ?: -1
            val tokenTypString = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_TOKEN_TYPE, null)?.asString()
            val tokenVersion = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_TOKEN_VERSION, null)?.asInt() ?: -1

            val jwtTokenTYpe = JWTTokenType.entries.find { it.name == tokenTypString }
            JWTAuthResult(
                userId = userId,
                tokenType = jwtTokenTYpe,
                tokenVersion,
                result.tokenCreateInstant,
                result.tokenTTL
            )
        } catch (_: JWTVerificationException) {
            null
        }
    }

    private fun prepareClaims(user: User, tokenType: JWTTokenType) = mapOf(
        JWTClaims.JWT_CLAIM_USER_NAME to user.userName,
        JWTClaims.JWT_CLAIM_USER_ID to user.id,
        JWTClaims.JWT_CLAIM_TOKEN_TYPE to tokenType.name,
        JWTClaims.JWT_CLAIM_TOKEN_VERSION to user.tokenVersion
    )

}