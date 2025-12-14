package com.sam.keystone.modules.user.dto.response

import com.fasterxml.jackson.annotation.JsonProperty

sealed interface LoginResponseDto {

    data class LoginResponseWithTokens(
        @field:JsonProperty("response") val tokens: TokenResponseDto,
    ) : LoginResponseDto

    data class LoginResponseWith2Fa(
        @field:JsonProperty("response") val mfaResponse: MFALoginResponseDto,
    ) : LoginResponseDto
}