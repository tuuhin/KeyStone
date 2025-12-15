package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.mfa.dto.MFADisableResponseDto
import com.sam.keystone.modules.user.dto.request.ProfileUpdateRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.UserProfileService
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
class RestProfileController(private val profileService: UserProfileService) {

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
    @Operation(summary = "Updated the user profile image")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun updateUserProfileImage(@RequestParam("image") file: MultipartFile, @AuthenticationPrincipal user: User) {
        profileService.uploadProfileImage(file, user)
    }

    @DeleteMapping("/avatar")
    @Operation(summary = "Delete user profile if present")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteUserProfile(@AuthenticationPrincipal user: User) {
        profileService.deleteProfileImage(user)
    }

    @GetMapping("2fa-status")
    @Operation(summary = "Updates users current profile")
    fun updateUserProfile(@AuthenticationPrincipal user: User): MFADisableResponseDto {
        val isActive = user.totpState?.isEnabled ?: false
        return MFADisableResponseDto(isDisabled = !isActive)
    }
}