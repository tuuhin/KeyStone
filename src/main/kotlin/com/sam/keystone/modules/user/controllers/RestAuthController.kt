package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.user.dto.request.*
import com.sam.keystone.modules.user.dto.response.*
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.*
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/auth")
@Tag(
    name = "User Authentication",
    description = "User management routes"
)
class RestAuthController(
    private val registerLoginService: AuthRegisterLoginService,
    private val tokenManagementService: AuthTokenManagementService,
    private val authVerifyService: AuthVerificationService,
    private val profileService: UserProfileService,
    private val passwordService: UserPasswordManagementService,
) {

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Creates a new user from the given credentials and send a verification mail")
    fun registerUser(@RequestBody request: RegisterUserRequest): RegisterUserResponseDto {
        return registerLoginService.createNewUser(request)
    }


    @PostMapping("/login", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(
        summary = "Checks the given credentials and prepares a new token pair",
        responses = [
            ApiResponse(
                description = "Normal Login for a user",
                responseCode = "200",
                content = [
                    Content(
                        schema = Schema(
                            oneOf = [
                                LoginResponseDto.LoginResponseWithTokens::class,
                                LoginResponseDto.LoginResponseWith2Fa::class,
                            ]
                        )
                    ),
                ]
            ),
        ]
    )
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun loginUser(@RequestBody request: LoginUserRequest): LoginResponseDto {
        return registerLoginService.loginUser(request)
    }


    @PostMapping("/resend_email")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Resends the email for user verification")
    fun resendVerificationMail(@RequestBody request: ResendEmailRequest) {
        authVerifyService.resendEmail(request)
    }


    @GetMapping("current_user")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Fetches the current authenticated user")
    @SecurityRequirement(name = "Authorization")
    fun getCurrentUser(@AuthenticationPrincipal user: User): UserResponseDto {
        return profileService.currentUserProfile(user)
    }

    @GetMapping("account-verify")
    @Operation(summary = "Informs the user if the current user is verified")
    fun currentUserStaus(@AuthenticationPrincipal user: User): UserVerificationStatusDto {
        val isVerified = user.verifyState?.isVerified ?: false
        return UserVerificationStatusDto(isVerified)
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Prepares a new token pair for the given refresh token")
    @SecurityRequirement(name = "Authorization")
    fun refreshToken(
        @RequestBody request: RefreshTokenRequest,
        @AuthenticationPrincipal user: User,
    ): TokenResponseDto {
        return tokenManagementService.handleRefreshTokenRequest(request, user)
    }


    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Log out a given user")
    @SecurityRequirement(name = "Authorization")
    fun logoutUser(@RequestBody request: RefreshTokenRequest, @AuthenticationPrincipal user: User) {
        tokenManagementService.blackListToken(request, user)
    }

    @DeleteMapping("/delete")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Delete the current authenticated user")
    @SecurityRequirement(name = "Authorization")
    fun deleteUser(@AuthenticationPrincipal user: User): MessageResponseDto {
        registerLoginService.deleteUser(user = user)
        return MessageResponseDto(message = "User removed successfully")
    }


    @PostMapping("/password/change")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Update current user password")
    @SecurityRequirement(name = "Authorization")
    fun changeUserPassword(
        @RequestBody request: ChangePasswordRequest,
        @AuthenticationPrincipal user: User,
    ): MessageResponseDto {
        passwordService.changeCurrentUserPassword(request, user)
        return MessageResponseDto("User password updated successfully")
    }

    @PostMapping("/password/reset/request")
    @Operation(summary = "Send a password reset request")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun resetUserPassword(@RequestBody request: ResetPasswordRequest) {
        passwordService.sendPasswordResetRequest(request)
    }

    @PostMapping("/password/reset/confirm")
    @Operation(summary = "Confirm password change")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun confirmPasswordRest(
        @RequestParam("token") token: String,
        @RequestBody request: ConfirmNewPasswordRequest,
    ): MessageResponseDto {
        passwordService.confirmPasswordChange(token, request.password)
        return MessageResponseDto("User password updated")
    }

}