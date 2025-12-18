package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.mfa.dto.MFADisableResponseDto
import com.sam.keystone.modules.user.dto.request.ProfileUpdateRequest
import com.sam.keystone.modules.user.dto.request.UpdateEmailRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.UserProfileService
import com.sam.keystone.modules.user.service.UserUpdateEmailService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile

@RestController
@RequestMapping("/api/profile")
@Tag(
    name = "User Profile Management",
    description = "Routes to manage profile of a given user"
)
@SecurityRequirement(name = "Authorization")
class RestProfileController(
    private val profileService: UserProfileService,
    private val emailUpdateService: UserUpdateEmailService,
) {

    @GetMapping("")
    @Operation(summary = "Current user with profile")
    fun currentUserProfile(@AuthenticationPrincipal user: User) =
        profileService.currentUserProfile(user)

    @PutMapping("")
    @Operation(summary = "Updates user profile")
    fun updateUserProfile(
        @RequestBody request: ProfileUpdateRequest,
        @AuthenticationPrincipal user: User,
    ): MessageResponseDto {
        profileService.updateUserProfile(request, user)
        return MessageResponseDto(message = "Profile update successfully")
    }

    @PostMapping("/avatar", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Updated the user profile image")
    fun updateUserProfileImage(@RequestParam("image") file: MultipartFile, @AuthenticationPrincipal user: User) {
        profileService.uploadProfileImage(file, user)
    }

    @DeleteMapping("/avatar")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete user profile if present")
    fun deleteUserProfile(@AuthenticationPrincipal user: User) {
        profileService.deleteProfileImage(user)
    }

    @GetMapping("2fa-status")
    @Operation(summary = "Updates users current profile")
    fun updateUserProfile(@AuthenticationPrincipal user: User): MFADisableResponseDto {
        val isActive = user.totpState?.isEnabled ?: false
        return MFADisableResponseDto(isDisabled = !isActive)
    }

    @PostMapping("/email-change")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Updates or change email address")
    fun updateEmailAddress(@RequestBody request: UpdateEmailRequest, @AuthenticationPrincipal user: User) {
        emailUpdateService.updateEmailAddressAndVerify(request, user)
    }

    @PostMapping("/email-change/cancel")
    @Operation(summary = "Cancels email change request")
    fun cancelUpdateEmailRequest(@AuthenticationPrincipal user: User): MessageResponseDto {
        emailUpdateService.cancelEmailUpdateRequest(user)
        return MessageResponseDto(message = "Email update request cancelled")
    }

    @PostMapping("/email-change/resend")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Resends email change verification mail")
    fun resendUpdateEmailRequest(@AuthenticationPrincipal user: User) {
        emailUpdateService.resendEmailVerificationRequest(user)
    }
}