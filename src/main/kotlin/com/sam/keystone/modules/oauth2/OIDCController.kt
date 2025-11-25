package com.sam.keystone.modules.oauth2

import com.sam.keystone.modules.oauth2.services.OIDCService
import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.security.models.OAuth2ClientUser
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/openid")
@Tag(
    name = "OpenID Connect",
    description = "Open ID connect routes"
)
@SecurityRequirement(name = "OAuth2 Authorization")
class OIDCController(private val service: OIDCService) {

    @GetMapping("/userinfo")
    @Operation(summary = "Authenticated user identity")
    @ResponseStatus(HttpStatus.OK)
    fun openIDUserInfo(@AuthenticationPrincipal user: OAuth2ClientUser): UserResponseDto? {

        return service.readUserInfoWithScope(user)
    }
}