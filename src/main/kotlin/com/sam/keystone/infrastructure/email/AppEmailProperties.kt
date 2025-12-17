package com.sam.keystone.infrastructure.email

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties(prefix = "app.email")
data class AppEmailProperties @ConstructorBinding constructor(
    val verifyEmailRedirect: String,
    val updateEmailRedirect: String,
)