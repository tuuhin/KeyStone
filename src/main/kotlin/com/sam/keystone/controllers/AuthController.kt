package com.sam.keystone.controllers

import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.dto.response.UserResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.mappers.toReposeDTO
import com.sam.keystone.services.UsersService
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.*


@RestController
@RequestMapping("/auth")
class AuthController(private val service: UsersService) {

    @PostMapping("/register")
    fun registerUser(@RequestBody request: RegisterUserRequest): ResponseEntity<TokenResponseDto> {
        return try {
            val newUser = service.createNewUser(request)
            ResponseEntity
                .status(HttpStatus.CREATED)
                .body(newUser)
        } catch (_: IllegalArgumentException) {
            ResponseEntity.badRequest().build()
        }
    }

    @PostMapping("/login")
    fun loginUser(@RequestBody request: LoginUserRequest): ResponseEntity<TokenResponseDto> {
        return try {
            val newUser = service.loginUser(request)
            ResponseEntity
                .status(HttpStatus.OK)
                .body(newUser)
        } catch (_: IllegalArgumentException) {
            ResponseEntity.badRequest().build()
        }
    }

    @SecurityRequirement(name = "Authorization")
    @GetMapping
    fun getCurrentUser(auth: Authentication): ResponseEntity<UserResponseDto> {
        val user = auth.principal as? User
        val response = user?.toReposeDTO() ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .build()

        return ResponseEntity.status(HttpStatus.OK).body(response)
    }
}