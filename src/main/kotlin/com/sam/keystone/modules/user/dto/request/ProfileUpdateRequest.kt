package com.sam.keystone.modules.user.dto.request

import com.fasterxml.jackson.annotation.JsonProperty

data class ProfileUpdateRequest(
    @field:JsonProperty("bio") val bio: String? = null,
    @field:JsonProperty("full_name") val fullName: String? = null,
)
