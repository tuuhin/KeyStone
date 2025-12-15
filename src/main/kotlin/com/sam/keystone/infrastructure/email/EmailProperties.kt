package com.sam.keystone.infrastructure.email

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties(prefix = "sendgrid")
data class EmailProperties @ConstructorBinding constructor(
    val apiKey: String,
    val senderEmail: String,
)