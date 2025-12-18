package com.sam.keystone.modules.core

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.core.exceptions.FileEmptyException
import com.sam.keystone.modules.core.exceptions.FileTooLargeException
import com.sam.keystone.modules.core.exceptions.InvalidFileFormatException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus

@ControllerAdvice
class CoreExceptionHandler {

    @ExceptionHandler(FileEmptyException::class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    fun handleUserValidationException(
        ex: FileEmptyException,
        request: HttpServletRequest,
    ): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "",
            error = "Bad Request",
            path = request.requestURI
        )
    }

    @ExceptionHandler(FileTooLargeException::class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    fun handleUserValidationException(
        ex: FileTooLargeException,
        request: HttpServletRequest,
    ): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "",
            error = "Bad Request",
            path = request.requestURI
        )
    }

    @ExceptionHandler(InvalidFileFormatException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleUserValidationException(
        ex: InvalidFileFormatException,
        request: HttpServletRequest,
    ): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "",
            error = "Bad Request",
            path = request.requestURI
        )
    }

}