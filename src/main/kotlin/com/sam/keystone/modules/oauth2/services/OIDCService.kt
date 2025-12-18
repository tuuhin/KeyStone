package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.infrastructure.buckets.S3StorageBucket
import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.security.models.OAuth2ClientUser
import org.springframework.stereotype.Service
import kotlin.time.Duration.Companion.hours

@Service
class OIDCService(
    private val repository: UserRepository,
    private val bucket: S3StorageBucket,
) {

    fun readUserInfoWithScope(client: OAuth2ClientUser): UserResponseDto {
        val userId = client.userId ?: throw UserAuthException("Cannot find the given user")
        val user = repository.findUserById(userId) ?: throw UserAuthException("Cannot find the given user")
        return user.currentUserProfile(isScoped = true, scopes = client.scopes)
    }

    fun User.currentUserProfile(isScoped: Boolean = true, scopes: Set<String>): UserResponseDto {
        return UserResponseDto(
            id = id,
            userName = userName,
            email = if (!isScoped || scopes.contains("email")) email else null,
            isVerified = if (!isScoped || scopes.contains("email")) verifyState?.isVerified ?: false else null,
            createdAt = if (!isScoped || scopes.contains("profile")) createdAt else null,
            bio = if (!isScoped || scopes.contains("profile")) profile?.bio else null,
            avatarUrl = if (!isScoped || scopes.contains("profile"))
                profile?.imageKey?.let { key -> bucket.provideSignedURL(key, 1.hours) }
            else null,
            fullName = if (!isScoped || scopes.contains("profile")) profile?.displayName else null,
        )
    }
}