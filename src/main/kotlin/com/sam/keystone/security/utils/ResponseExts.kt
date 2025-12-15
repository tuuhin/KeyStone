package com.sam.keystone.security.utils

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import kotlin.time.Duration

fun HttpServletResponse.setCookieExt(
    name: String,
    value: String? = null,
    isHttpOnly: Boolean = true,
    isSecure: Boolean = true,
    maxAge: Duration,
) {
    val cookie = Cookie(name, value).apply {
        this.isHttpOnly = isHttpOnly
        secure = isSecure
        path = "/"
        this.maxAge = maxAge.inWholeSeconds.toInt()
    }
    addCookie(cookie)
}