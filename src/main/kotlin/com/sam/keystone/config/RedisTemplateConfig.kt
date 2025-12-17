package com.sam.keystone.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.sam.keystone.infrastructure.redis.models.EmailUpdateData
import org.springframework.context.annotation.Bean
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.stereotype.Component

@Component
class RedisTemplateConfig {

    @Bean
    fun redisTemplate(
        connectionFactory: RedisConnectionFactory,
        mapper: ObjectMapper,
    ): RedisTemplate<String, Any> {

        val stringRedisSerializer = StringRedisSerializer()
        val jacksonSerializer = GenericJackson2JsonRedisSerializer(mapper)

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

    @Bean
    fun emailUpdateDataRedisTemplate(
        factory: RedisConnectionFactory,
        mapper: ObjectMapper,
    ): RedisTemplate<String, EmailUpdateData> {

        val updatedMapper = mapper.registerModule(KotlinModule.Builder().build())

        val keySerializer = StringRedisSerializer()
        val valueSerializer = Jackson2JsonRedisSerializer(updatedMapper, EmailUpdateData::class.java)

        val template = RedisTemplate<String, EmailUpdateData>().apply {
            setEnableTransactionSupport(true)
            connectionFactory = factory
            this.keySerializer = keySerializer
            this.valueSerializer = valueSerializer
        }
        template.afterPropertiesSet()
        return template
    }
}