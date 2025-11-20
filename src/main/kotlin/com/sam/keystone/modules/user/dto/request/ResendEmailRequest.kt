package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty

data class ResendEmailRequest(
    @field:JsonProperty("email")

    val email: String,
    @field:JsonProperty("resend_email_token")
    val resendKey: String,
)
