package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientListResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientResponseDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientRequestDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientResponseDto
import com.sam.keystone.modules.oauth2.exceptions.ClientNotFoundException
import com.sam.keystone.modules.oauth2.exceptions.RegisterClientValidationFailedException
import com.sam.keystone.modules.oauth2.mappers.toDto
import com.sam.keystone.modules.oauth2.mappers.toEntity
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.entity.User
import jakarta.transaction.Transactional
import org.springframework.stereotype.Service
import java.net.URI
import java.net.URISyntaxException

@Service
class OAuth2ClientService(
    private val repository: OAuth2ClientRepository,
    private val tokenGenerator: RandomTokenGeneratorConfig,
) {
    @Transactional
    fun createNewClient(request: RegisterClientRequestDto, user: User): RegisterClientResponseDto {

        // check request validity
        request.redirectURLs.forEach { url ->
            try {
                URI(url)
            } catch (_: URISyntaxException) {
                throw RegisterClientValidationFailedException("Failed to validate redirect uri :$url")
            }
        }

        val clientId = tokenGenerator.generateRandomToken(16, CodeEncoding.HEX_LOWERCASE)
        val clientSecret = tokenGenerator.generateRandomToken(16, CodeEncoding.HEX_LOWERCASE)
        val secretHash = tokenGenerator.hashToken(clientSecret)

        val entity = request.toEntity(clientId = clientId, clientSecretHash = secretHash, user = user)
        repository.save(entity)

        return RegisterClientResponseDto(
            clientName = request.clientName,
            clientId = clientId,
            clientSecret = clientSecret
        )
    }

    fun fetchAllClientsAssociatedToUser(user: User): OAuth2ClientListResponseDto {
        val clients = repository.findOAuth2ClientEntitiesByUser(user)
            .map { it.toDto() }
            .toSet()
        return OAuth2ClientListResponseDto(clients)
    }

    fun fetchClientWithClientIdAndUser(clientId: String, user: User): OAuth2ClientResponseDto {
        val entity = repository.findOAuth2ClientEntityByClientIdAndUser(clientId, user)
            ?: throw ClientNotFoundException(clientId)
        return entity.toDto()
    }

    fun updateClientMetaData(clientId: String, user: User, request: RegisterClientRequestDto): OAuth2ClientResponseDto {
        val entity = repository.findOAuth2ClientEntityByClientIdAndUser(clientId, user)
            ?: throw ClientNotFoundException(clientId)

        val updated = entity.also { entity ->
            entity.clientName = request.clientName
            entity.scopes.addAll(request.scopes)
            entity.redirectUris.addAll(request.redirectURLs)
            entity.grantTypes.addAll(request.grantType)
        }
        val saveResult = repository.save(updated)

        return saveResult.toDto()
    }

    @Transactional
    fun regenerateClientSecret(clientId: String, user: User): RegisterClientResponseDto {
        val entity = repository.findOAuth2ClientEntityByClientIdAndUser(clientId, user)
            ?: throw ClientNotFoundException(clientId)

        val clientSecret = tokenGenerator.generateRandomToken(16, CodeEncoding.HEX_LOWERCASE)
        val secretHash = tokenGenerator.hashToken(clientSecret)

        val updated = entity.also { it.secretHash = secretHash }
        repository.save(updated)

        return RegisterClientResponseDto(
            clientName = updated.clientName,
            clientId = clientId,
            clientSecret = clientSecret
        )
    }

    @Transactional
    fun deleteClient(clientId: String, user: User): MessageResponseDto {
        val entity = repository.findOAuth2ClientEntityByClientIdAndUser(clientId, user)
            ?: throw ClientNotFoundException(clientId)
        repository.delete(entity)

        return MessageResponseDto(message = "Client Deleted successfully")
    }
}