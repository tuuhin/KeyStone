package com.sam.keystone.exceptions

import com.sam.keystone.dto.response.ErrorResponseDto
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

@ControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(UserValidationException::class)
    fun handleUserValidationException(ex: UserValidationException, request: HttpServletRequest)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "Bad Request",
            path = request.requestURI
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response)
    }

    @ExceptionHandler(UserAuthException::class)
    fun handleUserAuthException(ex: UserAuthException, request: HttpServletRequest)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "Bad Request",
            path = request.requestURI
        )
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
    }

    @ExceptionHandler(TooManyRequestException::class)
    fun handlerUserVerification(ex: TooManyRequestException)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "Too many request made"
        )
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response)
    }

    @ExceptionHandler(UserVerificationException::class)
    fun handlerUserVerification(ex: UserVerificationException)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "User Verification"
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response)
    }

    @ExceptionHandler(Exception::class)
    fun handleGenericException(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message ?: "Internal server error",
            error = "Server Error",
            path = request.requestURI
        )
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response)
    }
}