package com.sam.keystone.modules.oauth2.exceptions

class RegisterClientValidationFailedException(override val message: String) :
    RuntimeException(message)