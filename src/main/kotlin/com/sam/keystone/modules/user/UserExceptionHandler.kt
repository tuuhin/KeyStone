package com.sam.keystone.modules.user

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

@ControllerAdvice
class UserExceptionHandler {

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


    @ExceptionHandler(UserVerificationException::class)
    fun handlerUserVerification(ex: UserVerificationException)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "User Verification"
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response)
    }

}