package com.sam.keystone.components

import com.sam.keystone.repository.UserRepository
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JWTAuthFilter(
    private val repository: UserRepository,
    private val tokenManager: JWTTokenManager,
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
        val userId = tokenManager.validateToken(token) ?: return
        val user = repository.findUserById(userId.toLong()) ?: return
        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority("USER"))
        )
        SecurityContextHolder.getContext().authentication = newAuth
    }
}