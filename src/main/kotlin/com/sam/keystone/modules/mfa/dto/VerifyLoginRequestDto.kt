package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class VerifyLoginRequestDto(
    @field:JsonProperty("mfa_token") val token: String,
    @field:JsonProperty("code") val code: String,
)