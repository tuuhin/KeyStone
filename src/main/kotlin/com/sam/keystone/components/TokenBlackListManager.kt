package com.sam.keystone.components

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.toJavaDuration

@Component
class TokenBlackListManager(private val template: StringRedisTemplate) {

    @Synchronized
    fun addToBlackList(token: String, expiry: Duration) {
        val operation = template.opsForValue()
        operation.set("$KEY_PREFIX:$token", "token", expiry.toJavaDuration())
    }

    @Synchronized
    fun isBlackListed(token: String): Boolean {
        return template.hasKey("$KEY_PREFIX:$token")
    }

    companion object {
        private const val KEY_PREFIX = "blacklist:refresh"
    }

}