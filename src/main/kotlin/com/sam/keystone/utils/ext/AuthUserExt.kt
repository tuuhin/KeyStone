package com.sam.keystone.utils.ext

import com.sam.keystone.entity.User
import com.sam.keystone.exceptions.UserAuthException
import org.springframework.security.core.Authentication

val Authentication.currentUser: User
    get() = principal as? User ?: throw UserAuthException("No authenticated user")