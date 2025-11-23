package com.sam.keystone.infrastructure.jwt

import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

@Component
class OAuth2JWTTokenGeneratorService(private val generator: JWTKeysGenerator) {

    @Value($$"${jwt.access-token-expiry-minutes}")
    lateinit var accessTokenLife: String

    @Value($$"${jwt.refresh-token-expiry-days}")
    lateinit var refreshTokenLife: String

    fun generateOAuthTokenPair(
        user: User,
        clientId: String,
        scopes: String? = null,
        accessTokenExpiry: Duration? = null,
        refreshTokenExpiry: Duration? = null,
    ): TokenResponseDto {

        val accessTokenDuration = accessTokenExpiry ?: (accessTokenLife).toInt().minutes
        val refreshTokenDuration = refreshTokenExpiry ?: (refreshTokenLife).toInt().days

        val baseMap: Map<String, Any?> = mapOf(
            JWT_CLAIM_USER_NAME to user.userName,
            JWT_CLAIM_USER_ID to user.id,
            JWT_CLAIM_CLIENT_ID to clientId,
            JWT_CLAIM_CLIENT_SCOPES to scopes
        )

        val accessToken = generator.generateToken(
            timeToLive = accessTokenDuration,
            claims = baseMap + mapOf(JWT_CLAIM_TOKEN_TYPE to JWTTokenType.ACCESS_TOKEN.name)
        )
        val refreshToken = generator.generateToken(
            timeToLive = refreshTokenDuration,
            claims = baseMap + mapOf(JWT_CLAIM_TOKEN_TYPE to JWTTokenType.REFRESH_TOKEN.name)
        )

        return TokenResponseDto(
            accessToken = accessToken,
            refreshToken = refreshToken
        )
    }

    fun introspectToken(token: String): OAuth2IntrospectionResult {
        val result = generator.validateToken(token)

        val clientId = result.claims.getOrDefault(JWT_CLAIM_CLIENT_ID, null)?.asString()
        val scopes = result.claims.getOrDefault(JWT_CLAIM_CLIENT_SCOPES, null)?.asString()
        val userId = result.claims.getOrDefault(JWT_CLAIM_USER_ID, null)?.asLong()
        val tokenTypeString = result.claims.getOrDefault(JWT_CLAIM_TOKEN_TYPE, null)?.asString()

        if (clientId == null || scopes == null || userId == null || tokenTypeString == null)
            throw JWTIntrospectionMissingClaims()

        return OAuth2IntrospectionResult(
            active = !result.isExpired,
            clientId = clientId,
            userId = userId,
            scope = scopes,
            issuedAt = result.tokenCreateInstant,
            expiresAt = result.tokenExpiryInstant,
            tokenType = JWTTokenType.valueOf(tokenTypeString)
        )
    }

    companion object {
        private const val JWT_CLAIM_CLIENT_ID = "oauth2_client_id"
        private const val JWT_CLAIM_CLIENT_SCOPES = "oauth2_client_scopes"
        private const val JWT_CLAIM_USER_NAME = "user_name"
        private const val JWT_CLAIM_USER_ID = "user_id"
        private const val JWT_CLAIM_TOKEN_TYPE = "token_type"
    }
}