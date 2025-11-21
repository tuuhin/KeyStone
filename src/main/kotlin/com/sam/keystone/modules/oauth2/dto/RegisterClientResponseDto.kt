package com.sam.keystone.modules.oauth2.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class RegisterClientResponseDto(
    @field:JsonProperty(value = "client_name")
    val clientName: String,

    @field:JsonProperty(value = "client_id")
    val clientId: String,

    @field:JsonProperty(value = "client_secret")
    val clientSecret: String,
)