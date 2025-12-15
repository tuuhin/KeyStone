package com.sam.keystone.security.filters

import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.security.exception.InvalidTokenVersionException
import com.sam.keystone.security.exception.JWTCookieNotFoundException
import com.sam.keystone.security.exception.JWTTokenExpiredException
import com.sam.keystone.security.exception.RequestedUserNotFoundException
import com.sam.keystone.security.utils.accessTokenCookie
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
        // put the authorize route list in here
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
            // we have an access token with an authorized user
            addAuthorizedUser(request)
            // if request is to log in even if we have an authenticated user redirect user to home
            if (request.requestURI.startsWith("/login")) {
                response.sendRedirect("/home")
                return
            }
            // continue the filter chain
            filterChain.doFilter(request, response)
        } catch (_: AuthenticationException) {
            // set up the session info about the next uri
            _logger.info("SETTING NEXT URI SESSION ")
            request.session.setAttribute("next", request.requestURI)
            request.session.setAttribute("next_query", request.queryString)
            // redirect the user back to client
            _logger.info("REDIRECTING TO LOG IN")
            response.sendRedirect("/login")
        } catch (e: Exception) {
            _logger.error("UNWANTED ERROR", e)
        }
    }

    private fun addAuthorizedUser(request: HttpServletRequest) {

        _logger.info("LOOKING FOR ACCESS TOKEN COOKIE")
        val tokenCookie = request.accessTokenCookie ?: throw JWTCookieNotFoundException()

        // authenticate via the cookie
        val result = jwtTokenService.validateAndReturnAuthResult(tokenCookie.value) ?: throw JWTTokenExpiredException()

        val user = repository.findUserById(result.userId) ?: throw RequestedUserNotFoundException()
        // token is invalid now
        if (result.tokenVersion != user.tokenVersion) throw InvalidTokenVersionException()

        // get the user if not route to log in

        val newAuth = UsernamePasswordAuthenticationToken.authenticated(
            user,
            null,
            listOf(SimpleGrantedAuthority(user.role.name))
        )
        SecurityContextHolder.getContext().authentication = newAuth

        _logger.info("NEW USER IS ATTACHED VIA COOKIE")
    }
}