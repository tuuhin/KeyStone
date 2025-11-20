package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

class UserResponseDto(

    @field:JsonProperty("user_id")
    val id: Long = 0L,

    @field:JsonProperty("email")
    val email: String,

    @field:JsonProperty("user_name")
    val userName: String,

    @field:JsonProperty("created_at")
    val createdAt: Instant,

    @field:JsonProperty("is_verified")
    val isVerified: Boolean = false,

    @field:JsonProperty("bio")
    var bio: String? = null,

    @field:JsonProperty("full_name")
    var fullName: String? = null,

    @field:JsonProperty("avatar_url")
    var avatarUrl: String? = null,
)