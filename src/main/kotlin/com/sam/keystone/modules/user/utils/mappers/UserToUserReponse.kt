package com.sam.keystone.modules.user.utils.mappers

import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User

fun User.toReposeDTO(isScoped: Boolean = false, scopes: Set<String> = emptySet()): UserResponseDto {
    return UserResponseDto(
        id = id,
        userName = userName,
        email = if (!isScoped || scopes.contains("email")) email else null,
        isVerified = if (!isScoped || scopes.contains("email")) verifyState?.isVerified ?: false else null,
        createdAt = if (!isScoped || scopes.contains("profile")) createdAt else null,
        bio = if (!isScoped || scopes.contains("profile")) profile?.bio else null,
        avatarUrl = if (!isScoped || scopes.contains("profile")) profile?.avatarUrl else null,
        fullName = if (!isScoped || scopes.contains("profile")) profile?.fullName else null,
    )
}