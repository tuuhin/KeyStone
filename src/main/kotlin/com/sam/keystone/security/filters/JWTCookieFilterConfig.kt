package com.sam.keystone.security.filters

import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.security.exception.JWTCookieNotFoundException
import com.sam.keystone.security.exception.JWTTokenExpiredException
import com.sam.keystone.security.exception.RequestedUserNotFoundException
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
class JWTCookieFilterConfig(
    private val repository: UserRepository,
    private val jwtTokenService: JWTTokenGeneratorService,
) : OncePerRequestFilter() {

    private val _logger by lazy { LoggerFactory.getLogger(this::class.java) }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val shouldFilter = arrayOf("/oauth2/authorize", "/home")
        val condition = shouldFilter.any { request.requestURI.startsWith(it) }
        return !condition
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            addAuthorizedUser(request)
            filterChain.doFilter(request, response)
        } catch (_: AuthenticationException) {
            if (!request.requestURI.startsWith("/logout")) {
                _logger.info("SETTING NEXT URI SESSION ")
                request.session.setAttribute("next", request.requestURI)
                request.session.setAttribute("next_query", request.queryString)
            }
            _logger.info("REDIRECTING TO LOG IN")
            response.sendRedirect("/login")
        } catch (e: Exception) {
            _logger.error("UNWANTED ERROR", e)
        }
    }

    private fun addAuthorizedUser(request: HttpServletRequest) {

        // get the request cookies
        val cookies = request.cookies?.toSet() ?: emptySet()
        val tokenCookie = cookies.find { it.name == "access_token" } ?: throw JWTCookieNotFoundException()

        // authenticate via the cookie
        val (userId, _) = jwtTokenService.validateToken(tokenCookie.value) ?: throw JWTTokenExpiredException()

        // get the user if not route to log in
        val user = repository.findUserById(userId) ?: throw RequestedUserNotFoundException()

        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority(user.role.name))
        )
        SecurityContextHolder.getContext().authentication = newAuth

        _logger.info("NEW USER IS ATTACHED VIA COOKIE")
    }
}