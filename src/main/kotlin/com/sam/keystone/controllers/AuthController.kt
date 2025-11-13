package com.sam.keystone.controllers

import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RefreshTokenRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.ErrorResponseDto
import com.sam.keystone.dto.response.MessageResponseDto
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.dto.response.UserResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.mappers.toReposeDTO
import com.sam.keystone.services.UsersService
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
    private val service: UsersService,
) {

    @PostMapping("/register")
    @Operation(summary = "Creates a new user from the given credentials and send a verification mail")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Email has been successfully send",
                content = [
                    Content(mediaType = "application/json", schema = Schema(MessageResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid user credentials",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun registerUser(@RequestBody request: RegisterUserRequest): ResponseEntity<MessageResponseDto> {
        val user = service.createNewUser(request)
        val response = MessageResponseDto("User created successfully, Check :${user.email} for verification")
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
                description = "Unauthenticated user",
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
        val newUser = service.loginUser(request)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(newUser)
    }

    @GetMapping("/verify")
    @Operation(summary = "Verifies a the register user")
    fun verifyUser(@RequestParam token: String): ResponseEntity<MessageResponseDto> {
        service.verifyRegisterToken(token)

        val response = MessageResponseDto("User is verified can continue to login")

        return ResponseEntity.status(HttpStatus.OK)
            .body(response)
    }

    @PostMapping("/resend_email")
    @Operation(summary = "Resends the email for user verification")
    fun resendVerificationMail(@RequestBody loginUserRequest: LoginUserRequest): ResponseEntity<Any> {
        service.resendEmail(loginUserRequest)
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
        // no authenticated used
        val user = auth.principal as? User ?: throw UserAuthException("No authenticated user")

        val newUser = service.generateNewTokenPairs(request, user)
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

        service.blackListToken(request)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
    }

}