package com.sam.keystone.modules.core.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class MessageResponseDto(
    @field:JsonProperty("message")
    val message: String = "",
)