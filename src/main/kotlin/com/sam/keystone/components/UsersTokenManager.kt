package com.sam.keystone.components

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class UsersTokenManager(private val template: StringRedisTemplate) {

    private val _hasher by lazy { MessageDigest.getInstance("SHA-256") }

    fun prepareTokenForUser(userId: Long, expiry: Duration = 10.minutes): String {
        // value removed
        template.opsForValue().get("$USER_PREFIX_KEY:$userId")?.let { token ->
            template.delete("$TOKEN_PREFIX_KEY:$token")
            template.delete("$USER_PREFIX_KEY:$userId")
        }
        // create a new token
        val token = UUID.randomUUID().toString()
        val hashedToken = hash(token)
        val timeout = expiry.toJavaDuration()
        template.opsForValue().set("$USER_PREFIX_KEY:$userId", hashedToken, timeout)
        template.opsForValue().set("$TOKEN_PREFIX_KEY:$hashedToken", userId.toString(), timeout)
        return token
    }

    fun validateToken(token: String): Long? {
        val hashedToken = hash(token)
        return template.opsForValue().get("$TOKEN_PREFIX_KEY:$hashedToken")?.toLongOrNull()
    }

    fun removeTokens(userId: Long) {
        template.opsForValue().get("$USER_PREFIX_KEY:$userId")?.let { token ->
            template.delete("$TOKEN_PREFIX_KEY:$token")
            template.delete("$USER_PREFIX_KEY:$userId")
        }
    }

    private fun hash(token: String): String {
        val bytes = token.toByteArray(charset = Charsets.UTF_8)
        return _hasher.digest(bytes).decodeToString()
    }

    companion object {
        private const val TOKEN_PREFIX_KEY = "verify:user_token"
        private const val USER_PREFIX_KEY = "verify:user"
    }
}