package com.sam.keystone.modules.mfa.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class MFADisableResponseDto(@field:JsonProperty("is_disabled") val isDisabled: Boolean = false)