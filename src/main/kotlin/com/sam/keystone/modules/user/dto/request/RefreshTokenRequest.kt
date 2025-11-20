package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty

data class RefreshTokenRequest(
    @field:JsonProperty("refresh_token")
    val token: String = "",
)
