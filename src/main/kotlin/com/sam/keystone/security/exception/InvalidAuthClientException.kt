package com.sam.keystone.security.exception

import org.springframework.security.core.AuthenticationException

class InvalidAuthClientException :
    AuthenticationException("Invalid client id cannot find any associate client with this")