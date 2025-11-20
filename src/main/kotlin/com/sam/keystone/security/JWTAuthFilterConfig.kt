package com.sam.keystone.security

import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.user.repository.UserRepository
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JWTAuthFilterConfig(
    private val repository: UserRepository,
    private val jwtTokenService: JWTTokenGeneratorService,
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        addAuthorizedUser(request)
        filterChain.doFilter(request, response)
    }

    private fun addAuthorizedUser(request: HttpServletRequest) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer")) return
        // removing the bearer
        val token = authHeader.substring(7)
        val (userId, _) = jwtTokenService.validateToken(token) ?: return
        val user = repository.findUserById(userId.toLong()) ?: return
        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority("USER"))
        )
        SecurityContextHolder.getContext().authentication = newAuth
    }
}