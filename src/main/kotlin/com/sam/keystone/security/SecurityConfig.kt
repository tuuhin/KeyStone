package com.sam.keystone.security

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
) {

    @Bean
    @Order(1)
    fun apiAuthenticationChain(http: HttpSecurity): SecurityFilterChain {
        // user based uri
        return http
            .securityMatcher("/api/auth/**", "/api/oauth2/clients/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { config ->
                config
                    .requestMatchers(
                        "/api/auth/resend_email",
                        "/api/auth/register",
                        "/api/auth/login",
                        "/api/auth/verify"
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
        // allow oauth2 and later resources server
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
        val swaggerPattens =
            arrayOf("/swagger-ui/**", "/swagger.html", "/v3/api-docs", "v3/api-docs/swagger-config")

        return http
            .authorizeHttpRequests { config ->
                config.requestMatchers(*swaggerPattens, "/login**").permitAll()
                    .anyRequest().authenticated()
            }
            .sessionManagement { config -> config.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) }
            .addFilterBefore(jwtCookieFilter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config ->
                config.authenticationEntryPoint { _, res, exp ->
                    exp.printStackTrace()
                    res.sendRedirect("/login")
                }
            }
            .build()
    }

    private val handleException = AuthenticationEntryPoint { _, response, authException ->
        response.contentType = "application/json"
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.writer.write("""{"error": "invalid_token", "error_description": "${authException.message}"}""")
    }
}