package com.sam.keystone.config


import com.sam.keystone.infrastructure.oidc.OIDCConfiguration
import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.security.OAuthFlow
import io.swagger.v3.oas.models.security.OAuthFlows
import io.swagger.v3.oas.models.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class SwaggerConfig(private val odicConnect: OIDCConfiguration) {

    @Bean
    fun configureSwagger(): OpenAPI {

        val config = odicConnect.readOIDCConfiguration()

        val info = Info().title("KeyStone")
            .version("0.0.1-SNAPSHOT")
            .description("OAuth2/OpenID Provider API with User Management")

        val httpBearerJwt = SecurityScheme()
            .type(SecurityScheme.Type.HTTP)
            .scheme("bearer")
            .bearerFormat("JWT")

        val oauth2Flows = OAuthFlows()
            .clientCredentials(
                OAuthFlow().tokenUrl(config.tokenEndpoint)
            )
            .authorizationCode(
                OAuthFlow()
                    .refreshUrl(config.authorizationEndpoint)
                    .authorizationUrl(config.authorizationEndpoint)

                    .tokenUrl(config.tokenEndpoint)
            )

        val oauth2Security = SecurityScheme()
            .type(SecurityScheme.Type.OAUTH2)
            .flows(oauth2Flows)

        val components = Components()
            .addSecuritySchemes("Authorization", httpBearerJwt)
            .addSecuritySchemes("OAuth2", oauth2Security)

        return OpenAPI()
            .info(info)
            .components(components)
    }
}
