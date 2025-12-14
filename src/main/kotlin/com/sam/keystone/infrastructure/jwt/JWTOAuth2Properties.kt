package com.sam.keystone.infrastructure.jwt

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties("jwt.oauth2")
data class JWTOAuth2Properties @ConstructorBinding constructor(
    val accessTokenExpiryMinutes: Int,
    val refreshTokenExpiryDays: Int,
)