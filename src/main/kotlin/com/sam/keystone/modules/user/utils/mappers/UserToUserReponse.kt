package com.sam.keystone.modules.user.utils.mappers

import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User

fun User.toReposeDTO(): UserResponseDto = UserResponseDto(
    id = id,
    userName = userName,
    email = email,
    isVerified = verifyState?.isVerified ?: false,
    createdAt = createdAt,
    bio = profile?.bio,
    avatarUrl = profile?.avatarUrl, fullName = profile?.fullName
)