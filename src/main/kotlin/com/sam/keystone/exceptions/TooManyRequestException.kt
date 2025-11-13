package com.sam.keystone.exceptions

class TooManyRequestException(override val message: String) : RuntimeException(message)