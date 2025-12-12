package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class MFAVerifyResponseDto(
    @field:JsonProperty("is_verified") val isVerified: Boolean = false,
    @field:JsonProperty("message") val message: String? = null,
)