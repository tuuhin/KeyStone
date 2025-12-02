package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.infrastructure.jwt.OAuth2JWTTokenGeneratorService
import com.sam.keystone.infrastructure.redis.TokenBlackListManager
import com.sam.keystone.modules.oauth2.dto.OAuth2RevokeResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenIntrospectResponseDto
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.oauth2.exceptions.ClientAuthFailedException
import com.sam.keystone.modules.oauth2.exceptions.ClientNotFoundException
import com.sam.keystone.modules.oauth2.exceptions.OAuth2UserException
import com.sam.keystone.modules.oauth2.mappers.toDto
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.stereotype.Service
import java.time.Duration
import java.time.Instant
import kotlin.time.toKotlinDuration

@Service
class OAuth2TokenService(
    private val repository: OAuth2ClientRepository,
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val jwtTokenGenerator: OAuth2JWTTokenGeneratorService,
    private val blackListManager: TokenBlackListManager,
) {

    private fun validateOAuth2ClientCredentials(
        clientId: String,
        secret: String? = null,
        user: User? = null,
    ): OAuth2ClientEntity {
        val client = repository.findOAuth2ClientEntityByClientId(clientId)
            ?: throw ClientNotFoundException(clientId)

        secret?.let {
            val secretHash = tokenGenerator.hashToken(secret)
            if (secretHash != client.secretHash) throw ClientAuthFailedException()
        }

        if (user?.id != client.user?.id) throw OAuth2UserException()
        return client
    }

    fun introspectToken(
        token: String,
        clientId: String,
        clientSecret: String,
        tokenHint: JWTTokenType = JWTTokenType.ACCESS_TOKEN,
    ): OAuth2TokenIntrospectResponseDto {
        // validate the client
        validateOAuth2ClientCredentials(clientId, secret = clientSecret)
        return try {
            // introspect the given token if failed then is active false
            jwtTokenGenerator.introspectToken(token, tokenHint)?.toDto() ?: throw Exception()
        } catch (_: Exception) {
            // other
            OAuth2TokenIntrospectResponseDto(active = false)
        }
    }


    fun revokeTokens(
        token: String,
        clientId: String,
        clientSecret: String? = null,
        tokenHint: JWTTokenType = JWTTokenType.ACCESS_TOKEN,
    ): OAuth2RevokeResponseDto {
        // validate the client credentials
        validateOAuth2ClientCredentials(clientId, secret = clientSecret)
        // introspect the given token
        val result = jwtTokenGenerator.introspectToken(token) ?: return OAuth2RevokeResponseDto()

        if (!blackListManager.isBlackListed(token, tokenHint)) {
            val ttl = Duration.between(Instant.now(), result.expiresAt).toKotlinDuration()
            // add the item to the blacklist so it cannot be used anymore
            if (ttl.isPositive()) blackListManager.addToBlackList(token, type = tokenHint, ttl)
        }
        // it's always a response
        return OAuth2RevokeResponseDto()
    }
}