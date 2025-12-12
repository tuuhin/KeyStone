package com.sam.keystone.infrastructure.otpauth

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties(prefix = "app.otp-auth")
data class OTPAuthProperties @ConstructorBinding constructor(
    val aesSecret: String,
    val issuer: String,
)