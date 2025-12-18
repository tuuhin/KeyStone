package com.sam.keystone.infrastructure.email

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding
import org.springframework.web.servlet.support.ServletUriComponentsBuilder

@ConfigurationProperties(prefix = "app.email")
data class AppEmailProperties @ConstructorBinding constructor(
    private val verifyEmailPath: String,
    private val updateEmailPath: String,
    private val passwordResetPath: String,
) {

    val verifyEmailRedirect: String
        get() = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(verifyEmailPath)
            .toUriString()

    val updateEmailRedirect: String
        get() = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(updateEmailPath)
            .toUriString()

    val passwordResetRedirect: String
        get() = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(passwordResetPath)
            .toUriString()
}