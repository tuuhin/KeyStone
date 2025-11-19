package com.sam.keystone.controllers

import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RefreshTokenRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.request.ResendEmailRequest
import com.sam.keystone.dto.response.*
import com.sam.keystone.entity.User
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.services.AuthRegisterLoginService
import com.sam.keystone.services.AuthTokenManagementService
import com.sam.keystone.services.AuthVerificationService
import com.sam.keystone.utils.ext.currentUser
import com.sam.keystone.utils.mappers.toReposeDTO
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.*


@RestController
@RequestMapping("/auth")
@Tag(
    name = "User Authentication",
    description = "User management routes"
)
class AuthController(
    private val registerLoginService: AuthRegisterLoginService,
    private val tokenManagementService: AuthTokenManagementService,
    private val authVerifyService: AuthVerificationService,
) {

    @PostMapping("/register")
    @Operation(summary = "Creates a new user from the given credentials and send a verification mail")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "User created and email send for verification",
                content = [
                    Content(
                        mediaType = "application/json",
                        schema = Schema(RegisterUserResponseDto::class)
                    ),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid user credentials to register",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun registerUser(@RequestBody request: RegisterUserRequest): ResponseEntity<RegisterUserResponseDto> {
        val response = registerLoginService.createNewUser(request)
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(response)
    }

    @PostMapping("/login")
    @Operation(summary = "Checks the given credentials and prepares a new token pair")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "New token pair created successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(TokenResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthorized user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid User",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun loginUser(@RequestBody request: LoginUserRequest): ResponseEntity<TokenResponseDto> {
        val newTokenPair = registerLoginService.loginUser(request)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(newTokenPair)
    }

    @GetMapping("/verify")
    @Operation(summary = "Verifies a the register user")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "User verified successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(TokenResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Cannot verify the given user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun verifyUser(@RequestParam token: String): ResponseEntity<MessageResponseDto> {
        authVerifyService.verifyRegisterToken(token)

        val response = MessageResponseDto("User is verified can continue to login")

        return ResponseEntity.status(HttpStatus.OK)
            .body(response)
    }

    @PostMapping("/resend_email")
    @Operation(summary = "Resends the email for user verification")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "204",
                description = "Mail send for user verification",
            ),
            ApiResponse(
                responseCode = "429",
                description = "Rate limit crossed",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Cannot verify the given user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun resendVerificationMail(@RequestBody request: ResendEmailRequest): ResponseEntity<Any> {
        authVerifyService.resendEmail(request)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
    }


    @GetMapping("current_user")
    @SecurityRequirement(name = "Authorization")
    @Operation(summary = "Fetches the current authenticated user")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Authenticated User",
                content = [
                    Content(mediaType = "application/json", schema = Schema(UserResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun getCurrentUser(auth: Authentication): ResponseEntity<UserResponseDto> {
        val user = auth.principal as? User
        val response = user?.toReposeDTO() ?: throw UserAuthException("No user found")
        return ResponseEntity.status(HttpStatus.OK).body(response)
    }


    @PostMapping("/refresh")
    @SecurityRequirement(name = "Authorization")
    @Operation(summary = "Prepares a new token pair for the given refresh token")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "New token pair created successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(TokenResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun refreshToken(
        @RequestBody request: RefreshTokenRequest,
        auth: Authentication,
    ): ResponseEntity<TokenResponseDto> {
        val newUser = tokenManagementService.handleRefreshTokenRequest(request, auth.currentUser)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(newUser)
    }


    @PostMapping("/logout")
    @SecurityRequirement(name = "Authorization")
    @Operation(summary = "Log out a given user")
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "204", description = "Token blacklisted successfully"),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun logoutUser(@RequestBody request: RefreshTokenRequest, auth: Authentication): ResponseEntity<Any> {
        // no authenticated used
        if (auth.principal !is User) throw UserAuthException("No authenticated user")

        tokenManagementService.blackListToken(request)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
    }

    @DeleteMapping("/delete")
    @SecurityRequirement(name = "Authorization")
    @Operation(summary = "Delete the current authenticated user")
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "202", description = "User deleted successfully"),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Delete cannot be performed",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun deleteUser(auth: Authentication): ResponseEntity<MessageResponseDto> {
        val authUser = auth.currentUser
        registerLoginService.deleteUser(userId = authUser.id)
        val message = MessageResponseDto(message = "User removed successfully")
        return ResponseEntity.status(HttpStatus.OK).body(message)
    }
}