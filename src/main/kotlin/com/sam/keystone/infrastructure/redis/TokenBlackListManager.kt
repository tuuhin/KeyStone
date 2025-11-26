package com.sam.keystone.infrastructure.redis

import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class TokenBlackListManager(private val template: StringRedisTemplate) {

    @Synchronized
    fun addToBlackList(token: String, type: JWTTokenType = JWTTokenType.REFRESH_TOKEN, expiry: Duration = 5.minutes) {
        val operation = template.opsForValue()
        val key = when (type) {
            JWTTokenType.ACCESS_TOKEN -> "$ACCESS_TOKEN_KEY_PREFIX:$token"
            JWTTokenType.REFRESH_TOKEN -> "$REFRESH_TOKEN_KEY_PREFIX:$token"
        }
        operation.set(key, "revoked", expiry.toJavaDuration())
    }

    @Synchronized
    fun isBlackListed(token: String, type: JWTTokenType = JWTTokenType.REFRESH_TOKEN): Boolean {
        val key = when (type) {
            JWTTokenType.ACCESS_TOKEN -> "$ACCESS_TOKEN_KEY_PREFIX:$token"
            JWTTokenType.REFRESH_TOKEN -> "$REFRESH_TOKEN_KEY_PREFIX:$token"
        }
        return template.hasKey(key)
    }

    companion object {
        private const val REFRESH_TOKEN_KEY_PREFIX = "blacklist:refresh"
        private const val ACCESS_TOKEN_KEY_PREFIX = "blacklist:access"
    }

}