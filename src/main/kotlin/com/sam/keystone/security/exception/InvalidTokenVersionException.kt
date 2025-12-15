package com.sam.keystone.security.exception

import org.springframework.security.core.AuthenticationException

class InvalidTokenVersionException : AuthenticationException("Invalid Token")