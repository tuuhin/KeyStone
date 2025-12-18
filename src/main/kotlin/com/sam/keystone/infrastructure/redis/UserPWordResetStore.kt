package com.sam.keystone.infrastructure.redis

import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.toJavaDuration

@Component
class UserPWordResetStore(
    private val template: RedisTemplate<String, Any>,
) {

    private val _logger by lazy { LoggerFactory.getLogger(this::class.java) }

    @Transactional
    fun saveToken(tokenHash: String, userId: Long, expiry: Duration = 2.hours) {
        _logger.debug("SAVING PASSWORD RESET TOKEN HASH :$expiry")
        val timeout = expiry.toJavaDuration()
        // get the previous token and delete the associated id
        template.opsForValue().get("$USER_P_WORD_RESET_TOKEN_KV:${userId}")?.let { previous ->
            template.delete("$USER_P_WORD_RESET_TOKEN_KV_REV:$previous")
        }
        // set the token with ttl
        template.opsForValue().set("$USER_P_WORD_RESET_TOKEN_KV:${userId}", tokenHash, timeout)
        template.opsForValue().set("$USER_P_WORD_RESET_TOKEN_KV_REV:$tokenHash", userId, timeout)
    }

    @Transactional
    fun getResetTokenData(tokenHash: String, deleteWhenDone: Boolean = true): Long? {
        _logger.info("LOOKING FOR PASSWORD RESET TOKEN HASH :$tokenHash")
        val userIdAsString = template.opsForValue().get("$USER_P_WORD_RESET_TOKEN_KV_REV:$tokenHash")?.toString()
        val userId = userIdAsString?.toLongOrNull() ?: return null

        _logger.debug("FOUND DATA FOR :$tokenHash")

        if (deleteWhenDone) {
            template.delete("$USER_P_WORD_RESET_TOKEN_KV:$userIdAsString")
            template.delete("${USER_P_WORD_RESET_TOKEN_KV_REV}:$tokenHash")
        }
        return userId
    }


    @Transactional
    fun requestCount(counterKey: String, maxValue: Int = 3, limit: Duration = 1.days): Boolean {
        val key = "$USER_P_WORD_RESENT_REQUEST_COUNT:$counterKey"
        val count = template.opsForValue().increment(key) ?: 1
        // set it for the first time
        if (count == 1L) template.expire(key, limit.toJavaDuration())

        return count <= maxValue
    }

    companion object {
        private const val USER_P_WORD_RESET_TOKEN_KV = "user:p_word-reset:id_to_token"
        private const val USER_P_WORD_RESET_TOKEN_KV_REV = "user:p_word-reset:token_to_id"
        private const val USER_P_WORD_RESENT_REQUEST_COUNT = "user:p_word-reset:request-count"
    }
}