package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

data class MFALoginResponseDto(
    @field:JsonProperty("mfa_required") val isEnabled: Boolean,
    @field:JsonProperty("mfa_token") val token: String = "",
)