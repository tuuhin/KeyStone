package com.sam.keystone.modules.oauth2

import com.nimbusds.jose.jwk.JWKSet
import com.sam.keystone.modules.oauth2.dto.OAuth2AuthorizationResponse
import com.sam.keystone.modules.oauth2.dto.OAuth2RevokeResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenIntrospectResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenResponseDto
import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import com.sam.keystone.modules.oauth2.services.OAuth2AuthService
import com.sam.keystone.modules.oauth2.services.OAuth2TokenService
import com.sam.keystone.modules.user.models.JWTTokenType
import com.sam.keystone.security.models.CodeChallengeMethods
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/oauth2")
@Tag(
    name = "OAuth Client Auth",
    description = "OAuth client authentication and authorization"
)
class OAuth2AuthController(
    private val authService: OAuth2AuthService,
    private val tokenService: OAuth2TokenService,
    private val jwkSet: JWKSet,
) {

    @GetMapping("/authorize")
    @Operation(summary = "Authorize a client")
    @SecurityRequirement(name = "Authorization")
    fun authorizeClient(
        @Parameter(
            description = "Authorization response type",
            example = "code",
            schema = Schema(allowableValues = ["code"])
        )
        @RequestParam("response_type", required = true)
        responseType: OAuth2ResponseType,
        @RequestParam("client_id")
        clientId: String,
        @RequestParam("redirect_uri")
        redirectUri: String,
        @Parameter(description = "List of scopes to be provided, should be space separated")
        @RequestParam("scope", required = false)
        scope: String?,
        @Parameter(name = "max_age", description = "Max age of the authorization code in seconds", required = false)
        @RequestParam("max_age")
        maxAge: Int = 120,
        @RequestParam(value = "code_challenge", required = true)
        codeChallenge: String,
        @Parameter(
            example = "plain",
            schema = Schema(allowableValues = ["plain", "sha256"])
        )
        @RequestParam(value = "code_challenge_method", required = true)
        codeChallengeMethod: CodeChallengeMethods,
        @RequestParam(value = "state", required = true)
        state: String,
        @RequestParam(value = "nonce", required = false)
        nonce: String? = null,
    ): OAuth2AuthorizationResponse {
        val response = authService.createTokenAndStorePKCE(
            responseType = responseType,
            clientId = clientId,
            redirectURI = redirectUri,
            scope = scope,
            maxTokenTTLInSeconds = maxAge,
            challengeCode = codeChallenge,
            challengeCodeMethod = codeChallengeMethod,
            nonce = nonce,
        )

        return response.copy(state = state)
    }


    @PostMapping(
        "/token",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE]
    )
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Creates a new token to use")
    fun createToken(
        @Parameter(
            description = "Grant type used during authorize",
            example = "authorization_code",
            schema = Schema(allowableValues = ["authorization_code", "client_credentials", "refresh_token"])
        )
        @RequestParam(value = "grant_type", required = true, defaultValue = "authorization_code")
        grantType: OAuth2GrantTypes,

        @Parameter(description = "Client Id created during registering a client")
        @RequestParam(value = "client_id", required = true)
        clientId: String,

        @Parameter(description = "Client secret provided during client creation")
        @RequestParam("client_secret", required = false)
        clientSecret: String = "",

        @Parameter(description = "Refresh token")
        @RequestParam("refresh_token", required = false)
        refreshToken: String = "",

        @Parameter(description = "Redirect uri set during authorization")
        @RequestParam("redirect_uri", required = true)
        redirectUri: String = "",

        @Parameter(description = "Authorization code from authorization process")
        @RequestParam("code", required = false)
        code: String = "",

        @Parameter(description = "Scopes for the client")
        @RequestParam("scope", required = false)
        scopes: String? = null,

        @Parameter(description = "If used PK CE with code_challenge during auth otherwise ignore")
        @RequestParam("code_challenge", required = false)
        codeVerifier: String = "",

        @RequestParam("state", required = false)
        state: String = "",
    ): OAuth2TokenResponseDto {
        val finalResponse = when (grantType) {
            OAuth2GrantTypes.AUTHORIZATION_CODE -> authService.validateTokenRequest(
                clientId = clientId,
                clientSecret = clientSecret,
                redirect = redirectUri,
                authCode = code,
                codeVerifier = codeVerifier,
                scopes = scopes
            )

            OAuth2GrantTypes.CLIENT_CREDENTIALS -> authService.createTokensForClientCredentialsGrant(
                clientId = clientId,
                clientSecret = clientSecret,
                scopes = scopes
            )

            OAuth2GrantTypes.REFRESH_TOKEN -> authService.handleRefreshTokenGrant(
                clientId = clientId,
                clientSecret = clientSecret,
                token = refreshToken,
                scopes = scopes,
            )
        }
        return finalResponse.copy(state = state)
    }


    @PostMapping(
        "/introspect",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE]
    )
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "validate a token (access or refresh) and get metadata about it.")
    fun introspectToken(
        @Parameter(description = "Token")
        @RequestParam token: String,

        @Parameter(description = "Token Hint", schema = Schema(allowableValues = ["access_token", "refresh_token"]))
        @RequestParam tokenHint: JWTTokenType = JWTTokenType.ACCESS_TOKEN,

        @Parameter(description = "Client Id")
        @RequestParam clientId: String,

        @Parameter(description = "Client Secret")
        @RequestParam clientSecret: String,
    ): OAuth2TokenIntrospectResponseDto {
        return tokenService.introspectToken(token, clientId, clientSecret, tokenHint)
    }


    @PostMapping(
        "/revoke",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE]
    )
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Invalidate this token so it cannot be used anymore")
    fun revokeToken(
        @Parameter(description = "Token")
        @RequestParam token: String,

        @Parameter(description = "Token Hint", schema = Schema(allowableValues = ["access_token", "refresh_token"]))
        @RequestParam tokenHint: JWTTokenType = JWTTokenType.ACCESS_TOKEN,

        @Parameter(description = "Client Id")
        @RequestParam clientId: String,

        @Parameter(description = "Client Secret")
        @RequestParam(required = false) clientSecret: String? = null,
    ): OAuth2RevokeResponseDto {
        return tokenService.revokeTokens(token, clientId = clientId, clientSecret, tokenHint)
    }


    @GetMapping("/jwks", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Returns the JSON Web Key Set containing the public keys used by the authorization server")
    fun showJWKS(): Map<String, Any> = jwkSet.toJSONObject()
}