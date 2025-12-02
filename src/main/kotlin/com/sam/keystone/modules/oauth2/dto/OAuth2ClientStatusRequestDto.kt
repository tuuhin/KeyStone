package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2ClientStatusRequestDto(
    @field:JsonProperty("is_valid")
    val isValid: Boolean,
)
