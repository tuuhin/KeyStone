package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank

data class ConfirmNewPasswordRequest(
    @field:NotBlank
    @field:JsonProperty("new_password")
    val password: String,
)
