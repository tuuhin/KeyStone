package com.sam.keystone.modules.oauth2.mappers

import com.sam.keystone.infrastructure.jwt.OAuth2IntrospectionResult
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenIntrospectResponseDto

fun OAuth2IntrospectionResult.toDto() = OAuth2TokenIntrospectResponseDto(
    issuedAt = issuedAt,
    expiresAt = expiresAt,
    active = active,
    userId = userId,
    clientId = clientId,
    scope = scope,
    tokenType = tokenType,
)