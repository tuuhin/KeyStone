package com.sam.keystone.infrastructure.redis

import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class MFATempSecretStore(
    private val template: RedisTemplate<String, Any>,
) {

    fun saveTempSecret(secret: String, userId: Long, ttl: Duration = 2.minutes) {
        template.opsForValue().set("$MFA_SETUP_USER:$userId", secret, ttl.toJavaDuration())
    }

    fun getTempSecret(userId: Long): String? {
        return template.opsForValue().getAndDelete("$MFA_SETUP_USER:$userId")?.toString()
    }

    companion object {
        private const val MFA_SETUP_USER = "mfa:setup:user"
    }
}