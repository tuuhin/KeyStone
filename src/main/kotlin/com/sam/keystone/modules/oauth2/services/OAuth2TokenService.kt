package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.infrastructure.jwt.OAuth2JWTTokenGeneratorService
import com.sam.keystone.infrastructure.redis.TokenBlackListManager
import com.sam.keystone.modules.oauth2.dto.*
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.oauth2.exceptions.*
import com.sam.keystone.modules.oauth2.mappers.toDto
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.stereotype.Service
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toKotlinDuration

@Service
class OAuth2TokenService(
    private val repository: OAuth2ClientRepository,
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val jwtTokenGenerator: OAuth2JWTTokenGeneratorService,
    private val blackListManager: TokenBlackListManager,
) {

    private fun validateOAuth2Client(clientId: String, secret: String, user: User): OAuth2ClientEntity {
        val client = repository.findOAuth2ClientEntityByClientId(clientId)
            ?: throw ClientNotFoundException(clientId)

        val secretHash = tokenGenerator.hashToken(secret)
        if (secretHash != client.secretHash) throw InvalidAuthorizeOrTokenParmsException(clientId)

        if (user.id != client.user?.id) throw OAuth2UserException()
        return client
    }

    fun introspectToken(request: OAuth2TokenRequestDto, user: User): OAuth2TokenIntrospectResponseDto {
        validateOAuth2Client(request.clientId, secret = request.secret, user = user)

        val result = jwtTokenGenerator.introspectToken(request.token) ?: throw OAuth2IntrospectionFailedException()
        return result.toDto()
    }


    fun invalidateAndCreateNewToken(request: OAuth2RefreshTokenRequestDto, currentUser: User): OAuth2TokenResponseDto {
        val client = validateOAuth2Client(request.clientId, secret = request.secret, user = currentUser)

        val result = jwtTokenGenerator.introspectToken(request.token) ?: throw OAuth2IntrospectionFailedException()
        if (result.userId != currentUser.id) throw OAuth2UserException()

        if (blackListManager.isBlackListed(request.token))
            throw OAuth2TokenInvalidException(token = JWTTokenType.REFRESH_TOKEN)

        val ttl = Duration.between(result.expiresAt, Instant.now()).toKotlinDuration()
        // add the item to the blacklist so it cannot be used anymore
        if (ttl.isPositive()) blackListManager.addToBlackList(request.token, type = JWTTokenType.REFRESH_TOKEN, ttl)

        // create a new token pair
        val accessTokenTTL = 15.minutes
        val refreshTokenTTL = 1.days

        val tokens = jwtTokenGenerator.generateOAuthTokenPair(
            user = currentUser,
            clientId = client.clientId,
            accessTokenExpiry = accessTokenTTL,
            refreshTokenExpiry = refreshTokenTTL
        )

        return OAuth2TokenResponseDto(
            accessToken = tokens.accessToken,
            expiry = accessTokenTTL.inWholeMilliseconds,
            refreshToken = if (client.allowRefreshTokens) tokens.refreshToken else null,
            refreshTokenExpiry = if (client.allowRefreshTokens) refreshTokenTTL.inWholeMilliseconds else 0L,
        )
    }


    fun revokeTokens(request: OAuth2TokenRequestDto, currentUser: User): OAuth2RevokeResponseDto {
        validateOAuth2Client(request.clientId, secret = request.secret, user = currentUser)

        val result = jwtTokenGenerator.introspectToken(request.token) ?: throw OAuth2IntrospectionFailedException()
        if (result.userId != currentUser.id) throw OAuth2UserException()

        if (blackListManager.isBlackListed(request.token, request.tokenType)) return OAuth2RevokeResponseDto()

        val ttl = Duration.between(result.expiresAt, Instant.now()).toKotlinDuration()
        // add the item to the blacklist so it cannot be used anymore
        if (ttl.isPositive())
            blackListManager.addToBlackList(request.token, type = request.tokenType, ttl)

        return OAuth2RevokeResponseDto()
    }
}