package com.sam.keystone.infrastructure.oidc

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class OIDCConfiguration {

    @Value($$"${jwt.issuer}")
    lateinit var jwtIssuer: String


    fun readOIDCConfiguration(): OIDCConfigurationDto {
        val baseEndpoint = jwtIssuer
        return OIDCConfigurationDto(
            issuer = jwtIssuer,
            authorizationEndpoint = "${baseEndpoint}oauth/authorize",
            tokenEndpoint = "${baseEndpoint}oauth/token",
            userinfoEndpoint = "${baseEndpoint}openid/userinfo",
            supportedScopes = listOf("openid", "email", "profile"),
            supportedGrantType = listOf("authorization_code"),
            supportedSubjectType = listOf("public"),
            responseType = listOf("code"),
            jWKSEndpoint = "${baseEndpoint}oauth/jwks",
            algorithm = listOf("RS256")
        )
    }
}