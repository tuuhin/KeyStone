package com.sam.keystone.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

data class TokenResponseDto(
    @field:JsonProperty("access_token")
    val accessToken: String,

    @field:JsonProperty("refresh_token")
    val refreshToken: String,
)
