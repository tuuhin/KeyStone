package com.sam.keystone.security

import com.sam.keystone.security.filters.JWTAuthFilterConfig
import com.sam.keystone.security.filters.OAuth2AuthFilterConfig
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val userAuthFilter: JWTAuthFilterConfig,
    private val oauth2Filter: OAuth2AuthFilterConfig,
) {

    @Bean
    @Order(1)
    fun authenticationFilterChain(http: HttpSecurity): SecurityFilterChain {
        // user based uri
        return http
            .securityMatcher("/auth/**", "/oauth2/clients/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { config ->
                config
                    .requestMatchers("/auth/resend_email", "/auth/register", "/auth/login", "/auth/verify")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
            }
            .sessionManagement { config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(userAuthFilter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config ->
                config.authenticationEntryPoint { _, response, authException ->
                    response.contentType = "application/json"
                    response.status = HttpServletResponse.SC_UNAUTHORIZED
                    response.writer.write("""{"error": "invalid_token", "error_description": "${authException.message}"}""")
                }
            }
            .build()
    }

    @Bean
    @Order(2)
    fun oauth2SecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        // allow oauth2 and later resources server
        return http
            .securityMatcher("/openid/*", "/oauth2/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { config ->
                config.requestMatchers("/oauth2/authorize", "/oauth2/token").permitAll()
                    .anyRequest().authenticated()
            }
            .sessionManagement { config ->
                config.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            .addFilterBefore(oauth2Filter, UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { config ->
                config.authenticationEntryPoint { _, response, authException ->
                    response.contentType = "application/json"
                    response.status = HttpServletResponse.SC_UNAUTHORIZED
                    response.writer.write("""{"error": "invalid_token", "error_description": "${authException.message}"}""")
                }
            }
            .build()
    }

    @Bean
    @Order(3)
    fun defaultFilterChain(http: HttpSecurity): SecurityFilterChain {
        // allow other request
        return http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth.anyRequest().permitAll()
            }
            .build()
    }
}