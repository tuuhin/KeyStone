package com.sam.keystone.infrastructure.redis

import com.sam.keystone.modules.oauth2.models.AuthorizeTokenModel
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class OAuth2AuthCodeStore(private val template: StringRedisTemplate) {

    @Transactional
    fun saveAuthTokenInfo(model: AuthorizeTokenModel, expiry: Duration = 5.minutes) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CLIENT_ID:${model.clientId}"
        // auth code and redirect uri
        operation.put(coreKey, OAUTH2_TOKEN_AUTH_TOKEN, model.code)
        operation.put(coreKey, OAUTH2_TOKEN_REDIRECT_URI, model.redirectURI)
        // optional scopes and grant types
        model.scopes?.let {
            operation.put(coreKey, OAUTH2_TOKEN_SCOPES, model.scopes)
        }
        model.grantType?.let {
            operation.put(coreKey, OAUTH2_TOKEN_GRANT_TYPES, model.grantType)
        }
        operation.expiration("$OAUTH2_CLIENT_ID:${model.clientId}")
            .expire(expiry.toJavaDuration())
    }

    @Transactional(readOnly = true)
    fun findAuthCodeViaClient(clientId: String): AuthorizeTokenModel? {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CLIENT_ID:$clientId"
        val authCode = operation.get(coreKey, OAUTH2_TOKEN_AUTH_TOKEN)
        val redirectURI = operation.get(coreKey, OAUTH2_TOKEN_REDIRECT_URI)
        val scopes = operation.get(coreKey, OAUTH2_TOKEN_SCOPES)
        val grantType = operation.get(coreKey, OAUTH2_TOKEN_GRANT_TYPES)

        if (authCode == null || redirectURI == null) return null
        return AuthorizeTokenModel(
            code = authCode,
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
    }

    companion object {
        private const val OAUTH2_CLIENT_ID = "oauth2:auth_code:client_id"

        //
        private const val OAUTH2_TOKEN_AUTH_TOKEN = "oauth2_auth_token"
        private const val OAUTH2_TOKEN_REDIRECT_URI = "oauth2_redirect_uri"
        private const val OAUTH2_TOKEN_SCOPES = "oauth2_scopes"
        private const val OAUTH2_TOKEN_GRANT_TYPES = "oauth2_grant_types"
    }
}