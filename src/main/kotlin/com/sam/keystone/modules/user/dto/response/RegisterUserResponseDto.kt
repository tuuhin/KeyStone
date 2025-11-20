package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

data class RegisterUserResponseDto(
    @field:JsonProperty("user")
    val user: UserResponseDto,

    @field:JsonProperty("resend_email_token")
    val resendToken: String,
)