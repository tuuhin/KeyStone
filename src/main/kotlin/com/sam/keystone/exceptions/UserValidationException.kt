package com.sam.keystone.exceptions

class UserValidationException(override val message: String) : RuntimeException(message)