package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2ClientListResponseDto(
    @field:JsonProperty("clients")
    val clients: Set<OAuth2ClientResponseDto> = emptySet(),
)