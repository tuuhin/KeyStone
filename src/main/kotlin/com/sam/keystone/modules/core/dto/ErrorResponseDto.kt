package com.sam.keystone.modules.core.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class ErrorResponseDto(
    @field:JsonProperty("message")
    val message: String,

    @field:JsonProperty("error")
    val error: String,

    @field:JsonProperty("path", required = false)
    val path: String? = null,
)