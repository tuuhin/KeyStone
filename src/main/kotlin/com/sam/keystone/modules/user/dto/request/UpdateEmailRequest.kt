package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class UpdateEmailRequest(
    @field:NotBlank
    @field:JsonProperty("password")
    val password: String,

    @field:Email
    @field:JsonProperty("new_email")
    val email: String,
)