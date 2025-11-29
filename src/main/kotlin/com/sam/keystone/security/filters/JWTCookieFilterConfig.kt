package com.sam.keystone.security.filters

import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.user.repository.UserRepository
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
class JWTCookieFilterConfig(
    private val repository: UserRepository,
    private val jwtTokenService: JWTTokenGeneratorService,
) : OncePerRequestFilter() {

    private val _logger by lazy { LoggerFactory.getLogger(this::class.java) }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val otherModeAuthFilters = arrayOf("/api", "/openid", "/resources")
        val swaggerPattens = arrayOf("/swagger", "/v3/api-docs", "v3/api-docs")
        val fullyOpenRoutes = arrayOf("/login")

        val shouldNotRoutes = buildList {
            addAll(otherModeAuthFilters)
            addAll(swaggerPattens)
            addAll(fullyOpenRoutes)
        }
        val condition = shouldNotRoutes.any { request.requestURI.startsWith(it) }
        return condition
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            addAuthorizedUser(request, response)
            filterChain.doFilter(request, response)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun addAuthorizedUser(request: HttpServletRequest, response: HttpServletResponse) {

        // get the request cookies
        val cookies = request.cookies?.toSet() ?: emptySet()
        val tokenCookie = cookies.find { it.name == "access_token" } ?: return response.sendRedirect("/login")

        // authenticate via the cookie
        val (userId, _) = jwtTokenService.validateToken(tokenCookie.value)
            ?: return response.sendRedirect("/login")

        // get the user if not route to log in
        val user = repository.findUserById(userId) ?: return response.sendRedirect("/login")

        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority(user.role.name))
        )
        SecurityContextHolder.getContext().authentication = newAuth

        _logger.info("NEW USER IS ATTACHED VIA COOKIE")
    }
}