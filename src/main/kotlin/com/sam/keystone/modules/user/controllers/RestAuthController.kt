package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.request.RefreshTokenRequest
import com.sam.keystone.modules.user.dto.request.RegisterUserRequest
import com.sam.keystone.modules.user.dto.request.ResendEmailRequest
import com.sam.keystone.modules.user.dto.response.*
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.AuthRegisterLoginService
import com.sam.keystone.modules.user.service.AuthTokenManagementService
import com.sam.keystone.modules.user.service.AuthVerificationService
import com.sam.keystone.modules.user.service.UserProfileService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
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


    @GetMapping("/verify")
    @Operation(summary = "Verifies a the register user")
    fun verifyUser(@RequestParam token: String): ResponseEntity<MessageResponseDto> {
        authVerifyService.verifyRegisterToken(token)

        val response = MessageResponseDto("User is verified can continue to login")

        return ResponseEntity.status(HttpStatus.OK)
            .body(response)
    }


    @PostMapping("/resend_email")
    @Operation(summary = "Resends the email for user verification")
    fun resendVerificationMail(@RequestBody request: ResendEmailRequest): ResponseEntity<Any> {
        authVerifyService.resendEmail(request)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
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
}