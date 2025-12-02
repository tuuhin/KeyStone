package com.sam.keystone.infrastructure.redis

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class UserVerificationTokenManager(
    private val template: RedisTemplate<String, Any>,
    private val tokenGenerator: RandomTokenGeneratorConfig,
) {

    @Transactional
    fun createVerificationToken(
        userId: Long,
        setRateLimit: Boolean = false,
        expiry: Duration = 30.minutes,
    ): String {
        val timeout = expiry.toJavaDuration()
        // delete the reverse token kv
        template.opsForValue().getAndDelete("$VERIFY_TOKEN_KV:$userId")?.let { token ->
            template.delete("$VERIFY_TOKEN_REVERSE_KV:$token")
        }
        // create a new token
        val token = tokenGenerator.generateRandomToken(encoding = CodeEncoding.HEX_LOWERCASE)
        val hashedToken = tokenGenerator.hashToken(token, encoding = CodeEncoding.HEX_LOWERCASE)
        // set the token with ttl
        template.opsForValue().set("$VERIFY_TOKEN_KV:$userId", hashedToken, timeout)
        template.opsForValue().set("$VERIFY_TOKEN_REVERSE_KV:$hashedToken", userId.toString(), timeout)
        if (setRateLimit) {
            val ttl = 5.minutes.toJavaDuration()
            template.opsForValue().set("$VERIFY_TOKEN_RATE:$userId", "1", ttl)
        }
        return token
    }

    @Transactional(readOnly = true)
    fun validateVerificationToken(token: String, deleteWhenDone: Boolean = true): Long? {
        val hashedToken = tokenGenerator.hashToken(token, encoding = CodeEncoding.HEX_LOWERCASE)
        val userIdTypeAny: Any? = template.opsForValue().get("$VERIFY_TOKEN_REVERSE_KV:$hashedToken")
        val userId = userIdTypeAny?.toString()?.toLongOrNull()
        if (userId != null && deleteWhenDone) {
            template.opsForValue().getAndDelete("$VERIFY_TOKEN_KV:$userIdTypeAny")?.let { token ->
                template.delete("$VERIFY_TOKEN_REVERSE_KV:$token")
            }
        }
        return userId
    }

    fun isVerificationEmailLimitActive(userId: Long): Boolean {
        return template.hasKey("$VERIFY_TOKEN_RATE:$userId")
    }

    @Transactional
    fun deleteUserTokens(userId: Long) {
        template.opsForValue().getAndDelete("$VERIFY_TOKEN_KV:$userId")?.let { token ->
            template.delete("$VERIFY_TOKEN_REVERSE_KV:$token")
        }
    }

    companion object {
        // tokens for verify
        private const val VERIFY_TOKEN_KV = "user:verify:id_to_token"
        private const val VERIFY_TOKEN_REVERSE_KV = "user:verify:token_to_id"
        private const val VERIFY_TOKEN_RATE = "user:verify:token_rate"
    }
}