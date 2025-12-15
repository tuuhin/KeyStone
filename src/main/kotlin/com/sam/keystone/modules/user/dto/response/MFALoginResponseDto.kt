package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import kotlin.time.Duration

data class MFALoginResponseDto(
    @field:JsonProperty("mfa_required") val isEnabled: Boolean,
    @field:JsonProperty("mfa_token") val token: String = "",
    @field:JsonIgnore val tokenValidity: Duration = Duration.ZERO,
)