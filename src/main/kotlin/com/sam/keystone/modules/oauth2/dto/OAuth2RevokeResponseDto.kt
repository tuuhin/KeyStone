package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2RevokeResponseDto(
    @field:JsonProperty("revoked")
    val isRevoked: Boolean = true,
)