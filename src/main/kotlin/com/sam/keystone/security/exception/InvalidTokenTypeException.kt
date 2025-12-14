package com.sam.keystone.security.exception

import org.springframework.security.core.AuthenticationException

class InvalidTokenTypeException : AuthenticationException("Invalid token type to handle authentication")