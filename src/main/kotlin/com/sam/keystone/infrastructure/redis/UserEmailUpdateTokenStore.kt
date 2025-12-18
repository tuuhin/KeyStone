package com.sam.keystone.infrastructure.redis

import com.sam.keystone.infrastructure.redis.models.EmailUpdateData
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.toJavaDuration

@Component
class UserEmailUpdateTokenStore(
    private val stringTemplate: StringRedisTemplate,
    private val emailDataTemplate: RedisTemplate<String, EmailUpdateData>,
) {

    private val _logger by lazy { LoggerFactory.getLogger(this::class.java) }

    @Transactional
    fun saveToken(tokenHash: String, data: EmailUpdateData, expiry: Duration = 2.hours) {
        _logger.debug("SAVING EMAIL UPDATE DATA WITH EXPIRY :$expiry")
        val timeout = expiry.toJavaDuration()
        // get the previous token and delete the associated id
        emailDataTemplate.opsForValue().get("$EMAIL_UPDATE_TOKEN_KV:${data.userId}")?.let { previous ->
            emailDataTemplate.delete("$EMAIL_UPDATE_META:$previous")
        }
        // set the token with ttl
        stringTemplate.opsForValue().set("$EMAIL_UPDATE_TOKEN_KV:${data.userId}", tokenHash, timeout)
        emailDataTemplate.opsForValue().set("$EMAIL_UPDATE_META:$tokenHash", data, timeout)
    }

    @Transactional
    fun getEmailUpdateData(tokenHash: String, deleteWhenDone: Boolean = true): EmailUpdateData? {
        _logger.debug("GET EMAIL UPDATE DATA FROM :$tokenHash")
        val tokenMeta = emailDataTemplate.opsForValue().get("$EMAIL_UPDATE_META:$tokenHash")
        _logger.debug("FOUND DATA FOR :$tokenHash")

        if (tokenMeta != null && deleteWhenDone) {
            emailDataTemplate.delete("$EMAIL_UPDATE_TOKEN_KV:${tokenMeta.userId}")
            emailDataTemplate.delete("${EMAIL_UPDATE_META}:$tokenHash")
        }
        return tokenMeta
    }


    @Transactional
    fun deleteSaveDataViaUserId(userId: Long) {
        _logger.debug("DELETING DATA FOR :$userId")
        stringTemplate.opsForValue().get("$EMAIL_UPDATE_TOKEN_KV:${userId}")?.let { token ->
            emailDataTemplate.delete("$EMAIL_UPDATE_META:$token")
        }
        emailDataTemplate.delete("$EMAIL_UPDATE_TOKEN_KV:${userId}")
    }

    @Transactional
    fun updateSendCount(userId: Long, maxValue: Int = 3, limit: Duration = 1.days): Boolean {
        val key = "$EMAIL_UPDATE_RESEND_COUNT:$userId"
        val count = stringTemplate.opsForValue().increment(key) ?: 1
        // set it for the first time
        if (count == 1L) stringTemplate.expire(key, limit.toJavaDuration())

        return count <= maxValue
    }

    companion object {
        private const val EMAIL_UPDATE_TOKEN_KV = "user:email-update:id_to_token"
        private const val EMAIL_UPDATE_META = "user:email-update:token_to_meta"
        private const val EMAIL_UPDATE_RESEND_COUNT = "user:email-update:resend-count"
    }
}