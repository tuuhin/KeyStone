package com.sam.keystone.modules.user.exceptions

class WeakPasswordException(override val message: String) : RuntimeException(message)