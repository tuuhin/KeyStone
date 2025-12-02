package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.utils.mappers.toReposeDTO
import com.sam.keystone.security.models.OAuth2ClientUser
import org.springframework.stereotype.Service

@Service
class OIDCService(private val repository: UserRepository) {

    fun readUserInfoWithScope(client: OAuth2ClientUser): UserResponseDto {
        val userId = client.userId ?: throw UserAuthException("Cannot find the given user")
        val user = repository.findUserById(userId) ?: throw UserAuthException("Cannot find the given user")
        return user.toReposeDTO(isScoped = true, scopes = client.scopes)
    }
}