package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class ResetPasswordRequest(
    @field:NotBlank
    @field:JsonProperty("user_name")
    val userName: String,

    @field:Email
    @field:JsonProperty("email")
    val email: String,
)