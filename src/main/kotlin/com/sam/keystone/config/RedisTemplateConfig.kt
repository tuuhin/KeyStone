package com.sam.keystone.config

import org.springframework.context.annotation.Bean
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.stereotype.Component

@Component
class RedisTemplateConfig {

    @Bean
    fun redisTemplate(connectionFactory: RedisConnectionFactory): RedisTemplate<String, Any> {
        val stringRedisSerializer = StringRedisSerializer()
        val jacksonSerializer = GenericJackson2JsonRedisSerializer()

        val template = RedisTemplate<String, Any>().apply {
            setEnableTransactionSupport(true)
            this.connectionFactory = connectionFactory
            keySerializer = stringRedisSerializer
            hashKeySerializer = stringRedisSerializer
            valueSerializer = jacksonSerializer
            hashValueSerializer = jacksonSerializer

        }
        template.afterPropertiesSet()
        return template
    }
}