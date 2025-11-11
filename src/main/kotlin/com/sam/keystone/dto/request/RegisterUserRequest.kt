package com.sam.keystone.dto.request

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class RegisterUserRequest(

    @field:Email
    @param:JsonProperty("email")
    val email: String,

    @field:NotBlank
    @field:Size(min = 3, max = 20)
    @param:JsonProperty("user_name")
    val userName: String,

    @field:NotBlank
    @field:Size(min = 3, max = 20)
    @param:JsonProperty("password")
    val password: String,
)
