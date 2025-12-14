package com.sam.keystone.security.utils

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest

val HttpServletRequest.bearerToken: String?
    get() {
        val authHeader = getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer")) return null
        return authHeader.substring(7)
    }

val HttpServletRequest.accessTokenCookie: Cookie?
    get() = cookies?.filterNotNull()?.find { it.name == "access_token" }
