package com.sam.keystone.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class AppPropertiesConfig {

    @Value($$"${app.verify-email-redirect}")
    private lateinit var _emailVerifyRedirect: String

    val emailVerifyRedirect: String
        get() = _emailVerifyRedirect
}