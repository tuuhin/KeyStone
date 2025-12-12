package com.sam.keystone.modules.mfa.controllers

import com.sam.keystone.modules.mfa.dto.*
import com.sam.keystone.modules.mfa.services.MFAEnableAndDisableService
import com.sam.keystone.modules.mfa.services.MFASetupAndVerifyService
import com.sam.keystone.modules.user.entity.User
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/api/2fa")
@RestController
@Tag(
    name = "Two Factor Authentication",
    description = "Enables the user to use multifactor authentication mechanisms"
)
@SecurityRequirement(name = "Authorization")
class MFAuthController(
    private val setupAndVerifyService: MFASetupAndVerifyService,
    private val enableAndDisableService: MFAEnableAndDisableService,
) {

    @PostMapping(
        "/setup",
        produces = [MediaType.APPLICATION_JSON_VALUE],
    )
    @Operation(summary = "Setup multi-factor authentication for the user")
    fun setup2fa(@AuthenticationPrincipal user: User): MFASetupResponseDto {
        return setupAndVerifyService.setup2fa(user)
    }

    @PostMapping(
        "/verify",
        produces = [MediaType.APPLICATION_JSON_VALUE],
        consumes = [MediaType.APPLICATION_JSON_VALUE]
    )
    @Operation(summary = "Verify multi-factor authentication authentication token")
    fun verify2Fa(
        @RequestBody request: MFACodeRequestDto,
        @AuthenticationPrincipal user: User,
    ): MFAVerifyResponseDto {
        return setupAndVerifyService.verify2FACode(request, user)
    }

    @PostMapping(
        "/enable",
        produces = [MediaType.APPLICATION_JSON_VALUE],
    )
    @Operation(summary = "Enabled multi-factor authentication for the given user")
    fun enable2FA(@AuthenticationPrincipal user: User): MFAEnableResponseDto {
        return enableAndDisableService.enable2FA(user)
    }

    @PostMapping(
        "/disable",
        produces = [MediaType.APPLICATION_JSON_VALUE],
        consumes = [MediaType.APPLICATION_JSON_VALUE]
    )
    @Operation(summary = "Disable multi-factor authentication for the given user")
    fun disable2FA(
        @RequestBody request: MFADisableRequestDto,
        @AuthenticationPrincipal user: User,
    ): MFADisableResponseDto {
        return enableAndDisableService.disable2FA(request, user)
    }

    @PostMapping("/backup-codes", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Generate new back up codes")
    fun regenerateBackupCodes(@AuthenticationPrincipal user: User): MFAEnableResponseDto {
        return enableAndDisableService.regenerateBackUpCodes(user)
    }

}