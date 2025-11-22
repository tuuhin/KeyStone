package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType

data class OAuth2AuthorizationResponse(
    @field:JsonProperty("authorization_code") val authCode: String,
    @field:JsonProperty("response_type") val type: OAuth2ResponseType,
    @field:JsonProperty("redirect_uri") val redirect: String,
    @field:JsonProperty("expires_millis") val expiresIn: Long = 0L,
    @field:JsonProperty("state") val state: String = "",
)