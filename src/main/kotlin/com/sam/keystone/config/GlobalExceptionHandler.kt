package com.sam.keystone.config

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.core.dto.FieldValidationResponseDto
import com.sam.keystone.security.exception.OAuth2ClientIDNotAttachedException
import com.sam.keystone.security.exception.TooManyRequestException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus


@ControllerAdvice
class GlobalExceptionHandler {

    @Value($$"${debug}")
    lateinit var isDebugMode: String

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

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationExceptions(
        ex: MethodArgumentNotValidException,
        request: HttpServletRequest,
    ): ResponseEntity<FieldValidationResponseDto> {
        val errors = buildSet {
            for (error in ex.bindingResult.allErrors) {
                val fieldName = (error as? FieldError)?.field ?: continue
                val errorMessage = error.defaultMessage ?: continue
                val invalid = FieldValidationResponseDto.FieldValidationErrorDto(fieldName, errorMessage)
                add(invalid)
            }
        }
        val response = FieldValidationResponseDto(errors = errors, request.requestURI)

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
            .body(response)
    }

    @ExceptionHandler(Exception::class)
    fun handleGenericException(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponseDto> {
        if (isDebugMode == "true") ex.printStackTrace()
        val response = ErrorResponseDto(
            message = ex.message ?: "Internal server error",
            error = "Server Error",
            path = request.requestURI
        )
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response)
    }
}