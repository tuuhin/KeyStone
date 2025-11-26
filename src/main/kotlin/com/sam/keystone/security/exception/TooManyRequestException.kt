package com.sam.keystone.security.exception

class TooManyRequestException(override val message: String) : RuntimeException(message)