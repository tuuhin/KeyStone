package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty
import com.sam.keystone.modules.user.models.JWTTokenType

data class OAuth2TokenRequestDto(
    @field:JsonProperty("client_id")
    val clientId: String,

    @field:JsonProperty("client_secret")
    val secret: String,

    @field:JsonProperty("token_type")
    val tokenType: JWTTokenType = JWTTokenType.ACCESS_TOKEN,

    @field:JsonProperty("token")
    val token: String,
)
