package com.sam.keystone.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class LoginUserRequest(

    @field:Email
    @param:JsonProperty("email", required = false)
    val email: String? = null,

    @field:NotBlank
    @field:Size(min = 3, max = 20)
    @param:JsonProperty("user_name", required = false)
    val userName: String? = null,

    @field:NotBlank
    @field:Size(min = 3, max = 20)
    @param:JsonProperty("password", required = true)
    val password: String,
)
