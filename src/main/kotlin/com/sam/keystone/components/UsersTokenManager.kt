package com.sam.keystone.components

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class UsersTokenManager(private val template: StringRedisTemplate) {

    private val _hasher by lazy { MessageDigest.getInstance("SHA-256") }

    fun createVerificationToken(
        userId: Long,
        setRateLimit: Boolean = false,
        expiry: Duration = 2.hours,
    ): String {
        val timeout = expiry.toJavaDuration()
        // delete the reverse token kv
        template.opsForValue().get("$VERIFY_TOKEN_KV:$userId")?.let { token ->
            template.delete("$VERIFY_TOKEN_REVERSE_KV:$token")
        }
        // create a new token
        val token = UUID.randomUUID().toString()
        val hashedToken = hash(token)
        // set the token with ttl
        template.opsForValue().set("$VERIFY_TOKEN_KV:$userId", hashedToken, timeout)
        template.opsForValue().set("$VERIFY_TOKEN_REVERSE_KV:$hashedToken", userId.toString(), timeout)
        if (setRateLimit) {
            val ttl = 5.minutes.toJavaDuration()
            template.opsForValue().set("$VERIFY_TOKEN_RATE:$userId", "1", ttl)
        }
        return token
    }

    fun validateVerificationToken(token: String, deleteWhenDone: Boolean = true): Long? {
        val hashedToken = hash(token)
        val userId = template.opsForValue().get("$VERIFY_TOKEN_REVERSE_KV:$hashedToken")?.toLongOrNull()
        if (userId != null && deleteWhenDone) deleteUserTokens(userId)
        return userId
    }

    fun isVerificationEmailLimitActive(userId: Long): Boolean {
        return !template.hasKey("$VERIFY_TOKEN_RATE:$userId")
    }

    fun deleteUserTokens(userId: Long) {
        template.opsForValue().get("$VERIFY_TOKEN_KV:$userId")?.let { token ->
            template.delete("$VERIFY_TOKEN_REVERSE_KV:$token")
            template.delete("$VERIFY_TOKEN_KV:$userId")
        }
    }

    fun hash(token: String): String {
        val bytes = token.toByteArray(charset = Charsets.UTF_8)
        return _hasher.digest(bytes).decodeToString()
    }

    companion object {
        // tokens for verify
        private const val VERIFY_TOKEN_KV = "user:verify:id_to_token"
        private const val VERIFY_TOKEN_REVERSE_KV = "user:verify:token_to_id"
        private const val VERIFY_TOKEN_RATE = "user:verify:token_rate"
    }
}