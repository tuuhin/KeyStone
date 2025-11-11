package com.sam.keystone.mappers

import com.sam.keystone.dto.response.UserResponseDto
import com.sam.keystone.entity.User

fun User.toReposeDTO(): UserResponseDto = UserResponseDto(
    id = id,
    userName = userName,
    email = email,
    createdAt = createdAt,
    bio = profile?.bio,
    avatarUrl = profile?.avatarUrl, fullName = profile?.fullName
)