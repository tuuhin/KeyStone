package com.sam.keystone.infrastructure.oidc

import com.sam.keystone.infrastructure.jwt.JWTProperties
import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import org.springframework.stereotype.Component

@Component
class OIDCConfiguration(private val properties: JWTProperties) {

    fun readOIDCConfiguration(): OIDCConfigurationDto {
        val baseEndpoint = properties.issuer
        return OIDCConfigurationDto(
            issuer = properties.issuer,
            authorizationEndpoint = "${baseEndpoint}oauth2/authorize",
            tokenEndpoint = "${baseEndpoint}oauth2/token",
            userinfoEndpoint = "${baseEndpoint}openid/userinfo",
            supportedScopes = listOf("openid", "email", "profile"),
            supportedGrantType = OAuth2GrantTypes.entries.map { it.value },
            responseType = OAuth2ResponseType.entries.map { it.simpleName },
            supportedSubjectType = listOf("public"),
            jWKSEndpoint = "${baseEndpoint}oauth2/jwks",
            algorithm = listOf("RS256")
        )
    }
}