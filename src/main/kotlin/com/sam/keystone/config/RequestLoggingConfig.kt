package com.sam.keystone.config

import org.springframework.context.annotation.Bean
import org.springframework.stereotype.Component
import org.springframework.web.filter.CommonsRequestLoggingFilter


@Component
class RequestLoggingConfig {

    @Bean
    fun logFilter(): CommonsRequestLoggingFilter {
        val filter = CommonsRequestLoggingFilter().apply {
            setIncludeQueryString(true);
            setMaxPayloadLength(10000);
            setIncludeHeaders(false);
        }
        return filter
    }
}