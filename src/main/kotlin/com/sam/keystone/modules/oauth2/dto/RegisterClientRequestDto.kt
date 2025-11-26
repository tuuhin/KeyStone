package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class RegisterClientRequestDto(

    @field:JsonProperty("client_name")
    val clientName: String,

    @field:JsonProperty(value = "redirect_uri")
    val redirectURLs: Set<String> = emptySet(),

    @field:JsonProperty(value = "scopes")
    val scopes: Set<String> = emptySet(),

    @field:JsonProperty(value = "grant_type")
    val grantType: Set<String> = emptySet(),

    @field:JsonProperty("allow_refresh_tokens")
    val refreshTokens: Boolean = true,
)
