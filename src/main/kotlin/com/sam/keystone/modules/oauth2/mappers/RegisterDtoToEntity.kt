package com.sam.keystone.modules.oauth2.mappers

import com.sam.keystone.modules.oauth2.dto.RegisterClientRequestDto
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.user.entity.User

fun RegisterClientRequestDto.toEntity(clientId: String, clientSecretHash: String, user: User) =
    OAuth2ClientEntity(
        clientId = clientId,
        allowRefreshTokens = refreshTokens,
        secretHash = clientSecretHash,
        user = user,
        clientName = clientName,
        redirectUris = redirectURLs.toMutableSet(),
        scopes = scopes.toMutableSet(),
        grantTypes = grantType.toMutableSet()
    )
