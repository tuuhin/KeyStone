package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class OAuth2ClientResponseDto(

    @field:JsonProperty(value = "client_name")
    val clientName: String = "",

    @field:JsonProperty(value = "client_id")
    val clientId: String = "",

    @field:JsonProperty(value = "redirect_uri")
    val redirectURLs: Set<String> = emptySet(),

    @field:JsonProperty(value = "scopes")
    val scopes: Set<String> = emptySet(),

    @field:JsonProperty(value = "grant_type")
    val grantType: Set<String> = emptySet(),

    @field:JsonProperty(value = "created_at")
    val createdAt: Instant = Instant.now(),

    @field:JsonProperty(value = "updated_at")
    val updatedAt: Instant = Instant.now(),

    @field:JsonProperty(value = "is_valid")
    val isValid: Boolean = false,
)