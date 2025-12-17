package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

data class UserVerificationStatusDto(@field:JsonProperty("is_verified") val isVerified: Boolean)