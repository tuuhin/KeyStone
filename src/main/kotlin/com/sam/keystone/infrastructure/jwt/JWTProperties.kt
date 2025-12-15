package com.sam.keystone.infrastructure.jwt

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties(prefix = "jwt")
data class JWTProperties @ConstructorBinding constructor(
    val audience: String,
    val issuer: String,
    val privateKeyPath: String,
    val publicKeyPath: String,
    val realm: String,
    val accessTokenExpiryMinutes: Int,
    val refreshTokenExpiryDays: Int,
)