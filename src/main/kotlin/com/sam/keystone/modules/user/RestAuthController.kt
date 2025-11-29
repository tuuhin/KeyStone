package com.sam.keystone.modules.user

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.request.RefreshTokenRequest
import com.sam.keystone.modules.user.dto.request.RegisterUserRequest
import com.sam.keystone.modules.user.dto.request.ResendEmailRequest
import com.sam.keystone.modules.user.dto.response.RegisterUserResponseDto
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.AuthRegisterLoginService
import com.sam.keystone.modules.user.service.AuthTokenManagementService
import com.sam.keystone.modules.user.service.AuthVerificationService
import com.sam.keystone.modules.user.utils.mappers.toReposeDTO
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
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
) {

    @PostMapping("/register")
    @Operation(summary = "Creates a new user from the given credentials and send a verification mail")
    fun registerUser(@RequestBody request: RegisterUserRequest): ResponseEntity<RegisterUserResponseDto> {
        val response = registerLoginService.createNewUser(request)
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(response)
    }


    @PostMapping("/login")
    @Operation(summary = "Checks the given credentials and prepares a new token pair")
    fun loginUser(@RequestBody request: LoginUserRequest): ResponseEntity<TokenResponseDto> {
        val newTokenPair = registerLoginService.loginUser(request)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(newTokenPair)
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
    @Operation(summary = "Fetches the current authenticated user")
    @SecurityRequirement(name = "Authorization")
    fun getCurrentUser(@AuthenticationPrincipal user: User): ResponseEntity<UserResponseDto> {
        val userDTO = user.toReposeDTO()
        return ResponseEntity.status(HttpStatus.OK).body(userDTO)
    }


    @PostMapping("/refresh")
    @Operation(summary = "Prepares a new token pair for the given refresh token")
    @SecurityRequirement(name = "Authorization")
    fun refreshToken(
        @RequestBody request: RefreshTokenRequest,
        @AuthenticationPrincipal user: User,
    ): ResponseEntity<TokenResponseDto> {
        val newUser = tokenManagementService.handleRefreshTokenRequest(request, user)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(newUser)
    }


    @PostMapping("/logout")
    @Operation(summary = "Log out a given user")
    @SecurityRequirement(name = "Authorization")
    fun logoutUser(
        @RequestBody request: RefreshTokenRequest,
        @AuthenticationPrincipal user: User,
    ): ResponseEntity<Any> {
        tokenManagementService.blackListToken(request, user)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
    }

    @DeleteMapping("/delete")
    @Operation(summary = "Delete the current authenticated user")
    @SecurityRequirement(name = "Authorization")
    fun deleteUser(@AuthenticationPrincipal user: User): ResponseEntity<MessageResponseDto> {
        registerLoginService.deleteUser(userId = user.id)
        val message = MessageResponseDto(message = "User removed successfully")
        return ResponseEntity.status(HttpStatus.OK).body(message)
    }
}