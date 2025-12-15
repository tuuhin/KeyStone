package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.buckets.S3StorageBucket
import com.sam.keystone.modules.user.dto.request.ProfileUpdateRequest
import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.repository.UserProfileRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.multipart.MultipartFile
import java.io.File
import java.util.*
import kotlin.time.Duration.Companion.hours

@Service
class UserProfileService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val repository: UserProfileRepository,
    private val bucket: S3StorageBucket,
) {

    @Transactional
    fun updateUserProfile(request: ProfileUpdateRequest, user: User) {
        // find the user update its contents
        val profile = repository.findUserProfileByUser(user) ?: throw UserAuthException("User not found")
        profile.bio = request.bio
        profile.displayName = request.fullName
        repository.save(profile)
    }

    @Transactional
    fun uploadProfileImage(file: MultipartFile, user: User) {

        val profile = repository.findUserProfileByUser(user) ?: throw UserAuthException("User not found")

        val hash = tokenGenerator.hashToken("${user.id}", CodeEncoding.HEX_LOWERCASE)
        val randomId = UUID.randomUUID().toString().take(8)
        val key = "$hash/$randomId-${file.name}"

        val tempDir = System.getProperty("java.io.tmpdir")
        val tmpFile = File.createTempFile(tempDir, "temp_file")
        try {
            // upload the file
            file.transferTo(tmpFile)
            bucket.uploadFile(key, tmpFile, contentType = file.contentType)
            // save the key in db
            profile.imageKey = key
            repository.save(profile)
        } finally {
            tmpFile.delete()
        }
    }

    @Transactional
    fun deleteProfileImage(user: User) {
        val profile = repository.findUserProfileByUser(user) ?: throw UserAuthException("User not found")

        val imageKey = profile.imageKey ?: throw Exception("No profile URL was set")
        bucket.deleteFile(imageKey)
        profile.imageKey = null
        repository.save(profile)
    }

    fun currentUserProfile(user: User): UserResponseDto {
        return UserResponseDto(
            id = user.id,
            userName = user.userName,
            email = user.email,
            isVerified = user.verifyState?.isVerified ?: false,
            createdAt = user.createdAt,
            updatedAt = user.updatedAt,
            bio = user.profile?.bio,
            avatarUrl = user.profile?.imageKey?.let { key -> bucket.provideSignedURL(key, 1.hours) },
            fullName = user.profile?.displayName,
        )
    }
}