package com.sam.keystone.modules.oauth2.mappers

import com.sam.keystone.modules.oauth2.dto.OAuth2ClientResponseDto
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity

fun OAuth2ClientEntity.toDto(): OAuth2ClientResponseDto = OAuth2ClientResponseDto(
    clientName = clientName,
    clientId = clientId,
    redirectURLs = redirectUris,
    scopes = scopes,
    grantType = grantTypes,
    updatedAt = updatedAt,
    createdAt = createdAt,
    isValid = isValid
)