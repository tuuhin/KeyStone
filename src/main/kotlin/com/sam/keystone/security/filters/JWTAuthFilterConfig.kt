package com.sam.keystone.security.filters

import com.fasterxml.jackson.databind.ObjectMapper
import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.security.exception.JWTTokenExpiredException
import com.sam.keystone.security.utils.bearerToken
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
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

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            addAuthorizedUser(request)
            filterChain.doFilter(request, response)
        } catch (e: JWTTokenExpiredException) {
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
        val (userId, _) = jwtTokenService.validateToken(token) ?: throw JWTTokenExpiredException()

        // get the user
        val user = repository.findUserById(userId) ?: return

        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority(user.role.name))
        )
        SecurityContextHolder.getContext().authentication = newAuth

        _logger.info("NEW USER IS ATTACHED")
    }
}