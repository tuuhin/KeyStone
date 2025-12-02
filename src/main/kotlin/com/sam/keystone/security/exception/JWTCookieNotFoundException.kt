package com.sam.keystone.security.exception

import org.springframework.security.core.AuthenticationException

class JWTCookieNotFoundException : AuthenticationException("Required cookie not found")