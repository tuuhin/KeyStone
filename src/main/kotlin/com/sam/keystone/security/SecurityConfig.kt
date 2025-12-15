package com.sam.keystone.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.security.filters.JWTAuthFilterConfig
import com.sam.keystone.security.filters.JWTCookieFilterConfig
import com.sam.keystone.security.filters.OAuth2AuthFilterConfig
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val jwtAuthFilter: JWTAuthFilterConfig,
    private val jwtCookieFilter: JWTCookieFilterConfig,
    private val oauth2Filter: OAuth2AuthFilterConfig,
    private val objectMapper: ObjectMapper,
) {

    @Bean
    @Order(1)
    fun apiAuthenticationChain(http: HttpSecurity): SecurityFilterChain {
        // user based uri
        return http
            .securityMatcher("/api/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { config ->
                config
                    .requestMatchers(
                        "/api/auth/resend_email",
                        "/api/auth/register",
                        "/api/auth/login",
                        "/api/auth/verify",
                        "/api/2fa/verify-login"
                    )
                    .permitAll()
                    .anyRequest()
                    .authenticated()
            }
            .sessionManagement { config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config -> config.authenticationEntryPoint(handleException) }
            .build()
    }

    @Bean
    @Order(2)
    fun resourceServerSecurityChain(http: HttpSecurity): SecurityFilterChain {
        // every request should be authenticated
        return http
            .securityMatcher("/openid/**", "/resources/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { config -> config.anyRequest().authenticated() }
            .sessionManagement { config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(oauth2Filter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config -> config.authenticationEntryPoint(handleException) }
            .build()
    }

    @Bean
    @Order(3)
    fun defaultFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { config ->
                config.ignoringRequestMatchers("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect")
            }
            .authorizeHttpRequests { config ->
                config
                    .requestMatchers("/home", "/oauth2/authorize").authenticated()
                    .anyRequest().permitAll()
            }
            .sessionManagement { config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(jwtCookieFilter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config ->
                // authentication issues
                config.authenticationEntryPoint { req, res, ex ->
                    ex.printStackTrace()
                    res.sendRedirect("/login")
                }
            }
            .build()
    }

    private val handleException = AuthenticationEntryPoint { _, response, authException ->
        response.contentType = "application/json"
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        val errorResponse = ErrorResponseDto(message = authException.message ?: "", error = "invalid_token")
        val responseString = objectMapper.writeValueAsString(errorResponse)
        response.writer.write(responseString)
    }
}