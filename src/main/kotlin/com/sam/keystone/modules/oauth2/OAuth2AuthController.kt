package com.sam.keystone.modules.oauth2

import com.nimbusds.jose.jwk.JWKSet
import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.oauth2.dto.*
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import com.sam.keystone.modules.oauth2.services.OAuth2AuthService
import com.sam.keystone.modules.oauth2.services.OAuth2TokenService
import com.sam.keystone.modules.user.utils.ext.currentUser
import com.sam.keystone.security.models.CodeChallengeMethods
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
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
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Authorize a client")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Authorization Code is created successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2AuthorizationResponse::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "407",
                description = "Cannot validate the provided parameters",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class))
                ]
            ),
        ]
    )
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
        @Parameter(description = "List of grant to be provided, should be space separated")
        @RequestParam("grant_type", required = false)
        grantType: String?,
        @RequestParam(value = "code_challenge", required = true)
        codeChallenge: String,
        @Parameter(
            example = "plain",
            schema = Schema(allowableValues = ["plain", "sha256"])
        )
        @RequestParam(value = "code_challenge_method", required = true)
        codeChallengeMethod: CodeChallengeMethods,
        @RequestParam(value = "state", required = false)
        state: String,
        @RequestParam(value = "nonce", required = false)
        nonce: String? = null,
    ): OAuth2AuthorizationResponse {

        val response = authService.createTokenAndStorePKCE(
            responseType = responseType,
            clientId = clientId,
            redirectURI = redirectUri,
            scope = scope,
            grantType = grantType,
            challengeCode = codeChallenge,
            challengeCodeMethod = codeChallengeMethod,
            nonce = nonce,
        )

        return response.copy(state = state)
    }


    @PostMapping("/token")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Creates a new token to use")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "201",
                description = "Authorization Code is created successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2TokenResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "407",
                description = "Cannot validate the provided parameters",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class))
                ]
            ),
        ]
    )
    fun createToken(
        @Parameter(description = "Authorization code from authorization process")
        @RequestParam("code", required = true)
        code: String,
        @RequestParam("client_id", required = true)
        clientId: String,
        @RequestParam("client_secret", required = false)
        clientSecret: String,
        @RequestParam("redirect_uri", required = true)
        redirectUri: String,
        @Parameter(description = "List of grant to be provided, should be space separated")
        @RequestParam("grant_type", required = true, defaultValue = "authorization_code")
        grantType: String,
        @RequestParam(value = "code_challenge", required = true)
        codeVerifier: String,
        @RequestParam(value = "state", required = false)
        state: String,
    ): OAuth2TokenResponseDto {

        val response = authService.validateTokenRequest(
            clientId = clientId,
            clientSecret = clientSecret,
            redirect = redirectUri,
            grantType = grantType,
            authCode = code,
            codeVerifier = codeVerifier
        )
        return response.copy(state = state)
    }

    @PostMapping("/introspect")
    @ResponseStatus(HttpStatus.OK)
    @SecurityRequirement(name = "OAuth2 Authorization")
    @Operation(summary = "validate a token (access or refresh) and get metadata about it.")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Show information related to the given token",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2TokenIntrospectResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "401",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Associate client don't have access",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "404",
                description = "Invalid parameters for the request body",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun introspectToken(@RequestBody request: OAuth2TokenRequestDto): OAuth2TokenIntrospectResponseDto {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        return tokenService.introspectToken(request, currentUser)
    }


    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.CREATED)
    @SecurityRequirement(name = "OAuth2 Authorization")
    @Operation(summary = "Validate the given token and blacklist it and generate a new token pair")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "201",
                description = "New token pair created successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2TokenResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "401",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Associate client don't have access",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "404",
                description = "Invalid parameters for the request body",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun refreshToken(@RequestBody request: OAuth2RefreshTokenRequestDto): OAuth2TokenResponseDto {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        return tokenService.invalidateAndCreateNewToken(request, currentUser)
    }


    @PostMapping("/revoke")
    @ResponseStatus(HttpStatus.OK)
    @SecurityRequirement(name = "OAuth2 Authorization")
    @Operation(summary = "Invalidate this token so it cannot be used anymore")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Token revoked successfully",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2RevokeResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "401",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Associate client don't have access",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "404",
                description = "Invalid parameters for the request body",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun revokeToken(@RequestBody request: OAuth2TokenRequestDto): OAuth2RevokeResponseDto {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        return tokenService.revokeTokens(request, currentUser)
    }


    @GetMapping("/jwks")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Returns the JSON Web Key Set containing the public keys used by the authorization server")
    fun showJWKS(): Map<String, Any> = jwkSet.toJSONObject()
}