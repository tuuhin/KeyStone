package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank

data class MFACodeRequestDto(
    @field:NotBlank
    @field:JsonProperty("code")
    val code: String = "",
)