package com.sam.keystone.modules.core.exceptions

class TooManyRequestException(override val message: String) : RuntimeException(message)