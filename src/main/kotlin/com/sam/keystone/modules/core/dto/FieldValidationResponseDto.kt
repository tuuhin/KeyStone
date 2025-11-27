package com.sam.keystone.modules.core.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class FieldValidationResponseDto(
    @field:JsonProperty("errors") val errors: Set<FieldValidationErrorDto> = emptySet(),
    @field:JsonProperty("path") val path: String? = null,
) {

    data class FieldValidationErrorDto(
        @field:JsonProperty("field_name") val fieldName: String,
        @field:JsonProperty("message") val message: String,
    )
}