package com.sam.keystone.modules.core

import com.sam.keystone.infrastructure.oidc.OIDCConfiguration
import com.sam.keystone.infrastructure.oidc.OIDCConfigurationDto
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/")
@Tag(name = "Foundation")
class HealthController(private val configuration: OIDCConfiguration) {


    @GetMapping("/health")
    @Operation(summary = "A indication that the server is working")
    fun healthStatus() = mapOf("status" to "Ok")

    @GetMapping("/.well-known/openid-configuration")
    @ResponseStatus(HttpStatus.OK)
    fun openIDConfiguration(): OIDCConfigurationDto {
        return configuration.readOIDCConfiguration()
    }
}