package com.sam.keystone.security.filters

import com.auth0.jwt.exceptions.JWTVerificationException
import com.fasterxml.jackson.databind.ObjectMapper
import com.sam.keystone.infrastructure.jwt.JWTClaims
import com.sam.keystone.infrastructure.jwt.JWTKeysGenerator
import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.models.JWTTokenType
import com.sam.keystone.security.exception.InvalidAuthClientException
import com.sam.keystone.security.exception.JWTTokenExpiredException
import com.sam.keystone.security.models.OAuth2ClientUser
import com.sam.keystone.security.utils.bearerToken
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class OAuth2AuthFilterConfig(
    private val generator: JWTKeysGenerator,
    private val clientRepository: OAuth2ClientRepository,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    private val _logger = LoggerFactory.getLogger(this::class.java)

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val isResourceRoute = request.requestURI.startsWith("/resource")
        val isOpenIDRoute = request.requestURI.startsWith("/openid")
        return !isResourceRoute && !isOpenIDRoute
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            addAuthorizedOAuth2Client(request)
            filterChain.doFilter(request, response)
        } catch (e: AuthenticationException) {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.contentType = "application/json"
            val errorResponse = ErrorResponseDto(message = e.message ?: "", error = "Token Invalid")
            val responseString = objectMapper.writeValueAsString(errorResponse)
            response.writer.write(responseString)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun addAuthorizedOAuth2Client(request: HttpServletRequest) {
        if (SecurityContextHolder.getContext().authentication != null) {
            _logger.warn("SECURITY CONTEXT IS ALREADY CONFIGURED")
            return
        }
        val token = request.bearerToken ?: return
        val result = try {
            generator.validateToken(token)
        } catch (_: JWTVerificationException) {
            throw JWTTokenExpiredException()
        }

        if (result.isExpired) throw JWTTokenExpiredException()
        //claims
        val scopes = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_CLIENT_SCOPES, null)?.asString()
        val userName = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_USER_NAME, null)?.asString()
        val tokenTypeString = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_TOKEN_TYPE, null)?.asString()
        val clientId = result.claims.getOrDefault(JWTClaims.JWT_CLAIM_CLIENT_ID, null)?.asString()

        // if client id is provided then it's a correct
        if (clientId == null || tokenTypeString != JWTTokenType.ACCESS_TOKEN.name) return
        val clientScopes = scopes?.split(" ")?.toSet() ?: emptySet()

        // check if this is a valid client
        val exists = clientRepository.existsOAuth2ClientEntityByClientId(clientId)

        if (!exists) throw InvalidAuthClientException()

        val authorities = clientScopes.map { SimpleGrantedAuthority("SCOPE_$it") }
        val principal = OAuth2ClientUser(scopes = clientScopes, claims = result.claims, username = userName)

        val authentication = BearerTokenAuthentication(
            principal,
            OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                token,
                result.tokenCreateInstant,
                result.tokenExpiryInstant,
                clientScopes
            ),
            authorities
        )
        SecurityContextHolder.getContext().authentication = authentication
        _logger.info("OAUTH2 CLIENT CONTEXT ADDED")
    }
}