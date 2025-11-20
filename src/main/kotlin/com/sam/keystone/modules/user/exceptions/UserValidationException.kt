package com.sam.keystone.modules.user.exceptions

class UserValidationException(override val message: String) : RuntimeException(message)