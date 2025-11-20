package com.sam.keystone.config

import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

@Component
class PasswordEncoderConfig {

    @Bean
    fun passwordEncoder(): PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
}