package com.sam.keystone.config

import com.sam.keystone.security.JWTAuthFilterConfig
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
class SecurityConfig(private val authFilter: JWTAuthFilterConfig) {


    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .authorizeHttpRequests { config ->
                config.requestMatchers("/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
            }
            .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter::class.java)
            .build()
    }

}