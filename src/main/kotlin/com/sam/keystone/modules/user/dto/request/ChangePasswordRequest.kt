package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank

data class ChangePasswordRequest(
    @field:NotBlank
    @field:JsonProperty("old_password")
    val oldPassword: String,

    @field:NotBlank
    @field:JsonProperty("new_password")
    val newPassword: String,
)