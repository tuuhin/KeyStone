package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import kotlin.time.Duration

data class TokenResponseDto(
    @field:JsonProperty("access_token")
    val accessToken: String,

    @field:JsonProperty("refresh_token")
    val refreshToken: String? = null,

    @field:JsonIgnore
    val accessTokenExpireIn: Duration = Duration.ZERO,

    @field:JsonIgnore
    val refreshTokenExpireIn: Duration = Duration.ZERO,
) {

    @get:JsonIgnore
    val accessTokenExpireInMillis: Long
        get() = accessTokenExpireIn.inWholeMilliseconds

    @get:JsonIgnore
    val refreshTokenExpiresInMillis: Long
        get() = refreshTokenExpireIn.inWholeMilliseconds
}
