package com.sam.keystone.infrastructure.redis

import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class MFASecretStore(
    private val template: RedisTemplate<String, Any>,
) {

    fun saveTempMFALoginToken(tokenHash: String, userId: Long, ttl: Duration = 1.minutes) {
        template.opsForValue().set("$MFA_LOGIN_USER:$tokenHash", userId, ttl.toJavaDuration())
    }

    fun getTempMFALoginChallenge(tokenHash: String): Long? {
        return template.opsForValue().get("$MFA_LOGIN_USER:$tokenHash")?.toString()?.toLong()
    }

    fun deleteMFALoginChallenge(tokenHash: String) = template.delete("$MFA_LOGIN_USER:$tokenHash")


    fun saveTempSetupSecret(secret: String, userId: Long, ttl: Duration = 2.minutes) {
        template.opsForValue().set("$MFA_SETUP_USER:$userId", secret, ttl.toJavaDuration())
    }

    fun getTempSetupSecret(userId: Long): String? {
        return template.opsForValue().get("$MFA_SETUP_USER:$userId")?.toString()
    }

    fun deleteTempSetupSecret(userId: Long) = template.delete("$MFA_SETUP_USER:$userId")

    companion object {
        private const val MFA_SETUP_USER = "mfa:setup:user"
        private const val MFA_LOGIN_USER = "mfa:login:challenge"
    }
}