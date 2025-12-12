package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class MFASetupResponseDto(
    @field:JsonProperty("secret")
    val secret: String,

    @field:JsonProperty("otpauth_url")
    val otpAuthUrl: String,

    @field:JsonProperty("qr_code")
    val encodedCode: String? = null,
)