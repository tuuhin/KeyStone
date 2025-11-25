package com.sam.keystone.config

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.security.exception.OAuth2ClientIDNotAttachedException
import com.sam.keystone.security.exception.TooManyRequestException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus

@ControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(TooManyRequestException::class)
    fun handlerUserVerification(ex: TooManyRequestException)
            : ResponseEntity<ErrorResponseDto> {
        val response = ErrorResponseDto(
            message = ex.message,
            error = "Too many request made"
        )
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response)
    }

    @ExceptionHandler(OAuth2ClientIDNotAttachedException::class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    fun handleTokenExpiredException(
        ex: OAuth2ClientIDNotAttachedException,
        request: HttpServletRequest,
    ): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "",
            error = "Too many request made",
            path = request.requestURI
        )
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