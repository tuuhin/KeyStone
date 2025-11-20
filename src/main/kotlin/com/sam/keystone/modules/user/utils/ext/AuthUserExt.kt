package com.sam.keystone.modules.user.utils.ext

import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import org.springframework.security.core.Authentication

val Authentication.currentUser: User
    get() = principal as? User ?: throw UserAuthException("No authenticated user")