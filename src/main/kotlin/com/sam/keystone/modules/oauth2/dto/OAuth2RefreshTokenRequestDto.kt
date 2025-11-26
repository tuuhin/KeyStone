package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2RefreshTokenRequestDto(
    @field:JsonProperty("client_id")
    val clientId: String,
    @field:JsonProperty("client_secret")
    val secret: String,
    @field:JsonProperty("refresh_token")
    val token: String,
)