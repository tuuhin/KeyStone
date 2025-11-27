package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
import jakarta.validation.constraints.NotEmpty
import org.hibernate.validator.constraints.Length

data class RegisterClientRequestDto(

    @field:Length(min = 5, message = "Client name is too small")
    @field:JsonProperty("client_name")
    val clientName: String,

    @field:NotEmpty(message = "Cannot create client without any redirect uri")
    @field:JsonProperty(value = "redirect_uri")
    val redirectURLs: Set<String> = emptySet(),

    @field:JsonProperty(value = "scopes")
    val scopes: Set<String> = emptySet(),

    @field:NotEmpty(message = "Need to address at-least one grant type")
    @field:JsonProperty(value = "grant_type")
    val grantType: Set<String> = emptySet(),

    @field:JsonProperty("allow_refresh_tokens")
    val refreshTokens: Boolean = true,
) {

    @get:JsonIgnore
    val validGrantTypes: Set<String>
        get() = grantType.intersect(OAuth2GrantTypes.grants)
}
