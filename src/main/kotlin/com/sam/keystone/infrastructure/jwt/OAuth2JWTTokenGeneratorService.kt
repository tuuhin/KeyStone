package com.sam.keystone.infrastructure.jwt

import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
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

    @Value($$"${jwt.oauth2.access-token-expiry-minutes}")
    lateinit var accessTokenLife: String

    @Value($$"${jwt.oauth2.refresh-token-expiry-days}")
    lateinit var refreshTokenLife: String

    fun generateOAuthTokenPair(
        clientId: String,
        user: User? = null,
        scopes: String? = null,
        createRefreshToken: Boolean = true,
        accessTokenExpiry: Duration? = null,
        refreshTokenExpiry: Duration? = null,
        responseType: OAuth2GrantTypes = OAuth2GrantTypes.AUTHORIZATION_CODE,
    ): TokenResponseDto {

        val accessTokenDuration = accessTokenExpiry ?: (accessTokenLife).toInt().minutes
        val refreshTokenDuration = refreshTokenExpiry ?: (refreshTokenLife).toInt().days


        val baseMap: Map<String, Any?> = buildMap {
            when (responseType) {
                OAuth2GrantTypes.AUTHORIZATION_CODE -> put(JWTClaims.JWT_CLAIM_SUB, user?.id ?: -1L)
                OAuth2GrantTypes.REFRESH_TOKEN -> put(JWTClaims.JWT_CLAIM_SUB, user?.id ?: -1L)
                OAuth2GrantTypes.CLIENT_CREDENTIALS -> put(JWTClaims.JWT_CLAIM_SUB, clientId)
            }
            put(JWTClaims.JWT_CLAIM_CLIENT_ID, clientId)
            put(JWTClaims.JWT_CLAIM_CLIENT_SCOPES, scopes)
        }

        val accessToken = generator.generateToken(
            timeToLive = accessTokenDuration,
            claims = baseMap + mapOf(JWTClaims.JWT_CLAIM_TOKEN_TYPE to JWTTokenType.ACCESS_TOKEN.name)
        )
        val refreshToken = if (!createRefreshToken || user == null) null
        else generator.generateToken(
            timeToLive = refreshTokenDuration,
            claims = baseMap + mapOf(JWTClaims.JWT_CLAIM_TOKEN_TYPE to JWTTokenType.REFRESH_TOKEN.name)
        )

        return TokenResponseDto(
            accessToken = accessToken,
            refreshToken = refreshToken,
            accessTokenExpireInMillis = accessTokenDuration.inWholeMilliseconds,
            refreshTokenExpiresInMillis = refreshTokenDuration.inWholeMilliseconds
        )
    }

    fun introspectToken(
        token: String,
        tokenHint: JWTTokenType = JWTTokenType.ACCESS_TOKEN,
    ): OAuth2IntrospectionResult? {
        val result = generator.validateToken(token)

        val clientId = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_CLIENT_ID, null)?.asString()
        val scopes = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_CLIENT_SCOPES, null)?.asString()
        val userId = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_USER_ID, null)?.asLong()
        val tokenTypeString = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_TOKEN_TYPE, null)?.asString()

        if (clientId == null || scopes == null || userId == null || tokenTypeString == null) return null
        val probableToken = JWTTokenType.valueOf(tokenTypeString)
        if (probableToken != tokenHint) return null

        return OAuth2IntrospectionResult(
            active = !result.isExpired,
            clientId = clientId,
            userId = userId,
            scope = scopes,
            issuedAt = result.tokenCreateInstant,
            expiresAt = result.tokenExpiryInstant,
            tokenType = probableToken
        )
    }
}