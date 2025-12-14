package com.sam.keystone.security.filters

import com.fasterxml.jackson.databind.ObjectMapper
import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.security.exception.InvalidTokenVersionException
import com.sam.keystone.security.exception.JWTTokenExpiredException
import com.sam.keystone.security.exception.RequestedUserNotFoundException
import com.sam.keystone.security.utils.bearerToken
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JWTAuthFilterConfig(
    private val repository: UserRepository,
    private val jwtTokenService: JWTTokenGeneratorService,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    private val _logger = LoggerFactory.getLogger(this::class.java)

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val shouldFilter = request.requestURI.startsWith("/api")
        return !shouldFilter
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            addAuthorizedUser(request)
            filterChain.doFilter(request, response)
        } catch (e: AuthenticationException) {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.contentType = "application/json"
            val errorResponse = ErrorResponseDto(message = e.message ?: "", error = "Token Invalid")
            val responseString = objectMapper.writeValueAsString(errorResponse)
            // Write a simple JSON body manually, as ControllerAdvice won't run.
            response.writer.write(responseString)
        }
    }

    private fun addAuthorizedUser(request: HttpServletRequest) {

        val token = request.bearerToken ?: return

        // validate the given token
        val result = jwtTokenService.validateAndReturnAuthResult(token) ?: throw JWTTokenExpiredException()

        val user = repository.findUserById(result.userId) ?: throw RequestedUserNotFoundException()

        // token is invalid now
        if (result.tokenVersion != user.tokenVersion) throw InvalidTokenVersionException()

        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority(user.role.name))
        )
        // add the authenticated user
        SecurityContextHolder.getContext().authentication = newAuth

        _logger.info("USER CONTEXT ADDED VIA JWT BEARER")
    }
}