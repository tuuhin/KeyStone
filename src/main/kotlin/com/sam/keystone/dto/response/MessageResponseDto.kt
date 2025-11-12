package com.sam.keystone.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

data class MessageResponseDto(
    @field:JsonProperty("message")
    val message: String = "",
)
