package com.sam.keystone.infrastructure.redis

import com.sam.keystone.security.models.AuthorizeTokenModel
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class OAuth2AuthCodeStore(private val template: StringRedisTemplate) {

    private val logger by lazy { LoggerFactory.getLogger(OAuth2AuthCodeStore::class.java) }


    @Transactional
    fun saveAuthTokenInfo(model: AuthorizeTokenModel, expiry: Duration = 5.minutes) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CLIENT_ID:${model.clientId}"
        // auth code and redirect uri
        operation.put(coreKey, OAUTH2_TOKEN_AUTH_TOKEN, model.authCode)
        operation.put(coreKey, OAUTH2_TOKEN_REDIRECT_URI, model.redirectURI)
        // optional scopes and grant types
        model.scopes?.let { scope ->
            if (scope.isEmpty()) return@let
            operation.put(coreKey, OAUTH2_TOKEN_SCOPES, scope)
        }
        model.grantType?.let { grants ->
            if (grants.isEmpty()) return@let
            operation.put(coreKey, OAUTH2_TOKEN_GRANT_TYPES, grants)
        }
        operation.expire(
            coreKey,
            expiry.toJavaDuration(),
            listOf(
                OAUTH2_TOKEN_AUTH_TOKEN,
                OAUTH2_TOKEN_REDIRECT_URI,
                OAUTH2_TOKEN_SCOPES,
                OAUTH2_TOKEN_GRANT_TYPES
            )
        )
        logger.debug("SAVING AUTH TOKEN INFO KEY :$coreKey EXPIRY :$expiry")
    }

    @Transactional(readOnly = true)
    fun findAuthCodeViaClient(clientId: String): AuthorizeTokenModel? {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CLIENT_ID:$clientId"
        val authCode = operation.get(coreKey, OAUTH2_TOKEN_AUTH_TOKEN)
        val redirectURI = operation.get(coreKey, OAUTH2_TOKEN_REDIRECT_URI)
        val scopes = operation.get(coreKey, OAUTH2_TOKEN_SCOPES)
        val grantType = operation.get(coreKey, OAUTH2_TOKEN_GRANT_TYPES)

        if (authCode == null || redirectURI == null) {
            logger.debug("CANNOT FIND AUTH TOKEN ENTRY :$coreKey")
            return null
        }
        logger.debug("FOUND AUTH TOKEN ENTRY :$coreKey")
        return AuthorizeTokenModel(
            authCode = authCode,
            redirectURI = redirectURI,
            scopes = scopes,
            grantType = grantType,
            clientId = clientId
        )
    }

    @Transactional
    fun deleteCodeAndClient(clientId: String) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CLIENT_ID:$clientId"
        operation.delete(
            coreKey,
            OAUTH2_TOKEN_AUTH_TOKEN,
            OAUTH2_TOKEN_REDIRECT_URI,
            OAUTH2_TOKEN_SCOPES,
            OAUTH2_TOKEN_GRANT_TYPES
        )
        logger.debug("DELETING AUTH TOKEN ENTRY :$coreKey")
    }

    fun saveClientNonce(clientId: String, nonce: String, expiry: Duration = 2.minutes) {
        val operation = template.opsForValue()
        val key = "$OIDC_NONCE:$clientId"
        operation.set(key, nonce, expiry.toJavaDuration())
        logger.debug("SAVING NONCE FOR OIDC :$key")
    }

    fun getClientNonce(clientId: String): String? {
        val operation = template.opsForValue()
        val key = "$OIDC_NONCE:$clientId"
        val result = operation.getAndDelete(key)
        logger.debug("FOUND NONCE FOR OIDC :$key DELETING THIS NOW")
        return result
    }

    companion object {
        private const val OAUTH2_CLIENT_ID = "oauth2:auth_code:client_id"
        private const val OIDC_NONCE = "oidc:nonce:client_id"

        //
        private const val OAUTH2_TOKEN_AUTH_TOKEN = "oauth2_auth_token"
        private const val OAUTH2_TOKEN_REDIRECT_URI = "oauth2_redirect_uri"
        private const val OAUTH2_TOKEN_SCOPES = "oauth2_scopes"
        private const val OAUTH2_TOKEN_GRANT_TYPES = "oauth2_grant_types"
    }
}