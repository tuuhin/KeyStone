package com.sam.keystone.modules.oauth2

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.oauth2.exceptions.*
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus

@ControllerAdvice
class OAuth2ExceptionHandler {

    @ExceptionHandler(ClientInvalidException::class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    fun handleException(ex: ClientInvalidException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Cannot Accept",
            error = "Client Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(ClientNotFoundException::class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    fun handleException(ex: ClientNotFoundException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Not found",
            error = "Client Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(InvalidAuthorizeOrTokenParmsException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleException(ex: InvalidAuthorizeOrTokenParmsException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message,
            error = "Client Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(OAuth2AuthCodeFailedException::class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    fun handleException(ex: OAuth2AuthCodeFailedException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Cannot give proper code so cannot access",
            error = "OAuth2 Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(OAuth2InvalidResponseTypeException::class)
    @ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
    fun handleException(ex: OAuth2InvalidResponseTypeException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Only accept code as repose type",
            error = "OAuth2 Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(PKCEInvalidException::class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    fun handleException(ex: PKCEInvalidException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "PK-CE cannot be processed",
            error = "OAuth2 Error",
            path = request.requestURI
        )
    }


    @ExceptionHandler(RegisterClientValidationFailedException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleException(ex: RegisterClientValidationFailedException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message,
            error = "Client Error",
            path = request.requestURI
        )
    }


    @ExceptionHandler(OAuth2UserException::class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    fun handleException(ex: OAuth2UserException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Invalid user",
            error = "Oauth2 Error",
            path = request.requestURI
        )
    }

    @ExceptionHandler(OAuth2TokenInvalidException::class)
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    fun handleException(ex: OAuth2TokenInvalidException, request: HttpServletRequest): ErrorResponseDto {
        return ErrorResponseDto(
            message = ex.message ?: "Invalid token",
            error = "Oauth2 Error",
            path = request.requestURI
        )
    }
}