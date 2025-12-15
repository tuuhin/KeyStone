package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class MFAEnableResponseDto(
    @field:JsonProperty("is_enabled") val enabled: Boolean = false,
    @field:JsonProperty("backup_codes") val backupCodes: List<String> = emptyList(),
)