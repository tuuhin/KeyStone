package com.sam.keystone.modules.mfa

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.mfa.exceptions.*
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus

@ControllerAdvice
class MFAExceptionHandler {

    @ExceptionHandler(MFAAlreadyEnabledException::class)
    @ResponseStatus(HttpStatus.CONFLICT)
    fun handleException(ex: MFAAlreadyEnabledException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Multi-factor authentication is already enabled for this account.",
            error = "Conflict Error",
            path = request.requestURI
        )
    }


    @ExceptionHandler(MFANotEnabledException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleException(ex: MFANotEnabledException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Multi-factor authentication is not currently enabled for this account.",
            error = "Bad request",
            path = request.requestURI
        )
    }

    @ExceptionHandler(MFASetupAlreadyDoneException::class)
    @ResponseStatus(HttpStatus.CONFLICT)
    fun handleException(ex: MFASetupAlreadyDoneException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "MFA setup process has already been completed.",
            error = "Conflict Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(MFASetupIncompleteException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleException(ex: MFASetupIncompleteException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "MFA setup is incomplete. Please restart the setup process.",
            error = "Bad request",
            path = request.requestURI
        )
    }

    @ExceptionHandler(TOTPCodeInvalidException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleException(ex: TOTPCodeInvalidException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "The provided Time-based One-Time Password (TOTP) code is invalid.",
            error = "Bad Request",
            path = request.requestURI
        )
    }

}