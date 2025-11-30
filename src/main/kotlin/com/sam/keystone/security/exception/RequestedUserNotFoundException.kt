package com.sam.keystone.security.exception

import org.springframework.security.core.AuthenticationException

class RequestedUserNotFoundException : AuthenticationException("User cannot be determined from the given credentials")