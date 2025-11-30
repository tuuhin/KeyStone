package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.jwt.OAuth2JWTTokenGeneratorService
import com.sam.keystone.infrastructure.jwt.OIDCJWTTokenGenerator
import com.sam.keystone.infrastructure.redis.OAuth2AuthCodeStore
import com.sam.keystone.infrastructure.redis.OAuth2CodePKCEStore
import com.sam.keystone.infrastructure.redis.TokenBlackListManager
import com.sam.keystone.modules.oauth2.dto.OAuth2AuthorizationResponse
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenResponseDto
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.oauth2.exceptions.*
import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.models.JWTTokenType
import com.sam.keystone.security.models.AuthorizeTokenModel
import com.sam.keystone.security.models.CodeChallengeMethods
import com.sam.keystone.security.models.PKCEModel
import org.springframework.stereotype.Service
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

@Service
class OAuth2AuthService(
    private val repository: OAuth2ClientRepository,
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val challengesStore: OAuth2CodePKCEStore,
    private val authCodeStore: OAuth2AuthCodeStore,
    private val jwtTokenGenerator: OAuth2JWTTokenGeneratorService,
    private val oidcTokenGenerator: OIDCJWTTokenGenerator,
    private val blackListManager: TokenBlackListManager,
) {

    fun validateClientIdWithParameters(
        clientId: String,
        redirectURI: String,
        scope: String? = null,
    ): OAuth2ClientEntity {

        val entity = repository.findOAuth2ClientEntityByClientId(clientId)
            ?: throw ClientNotFoundException(clientId)

        if (!entity.isValid) throw ClientInvalidException()

        // check if the provided data is correct
        if (redirectURI !in entity.redirectUris) throw InvalidAuthorizeOrTokenParmsException(clientId)

        // check for matching scopes
        scope?.split(" ")?.let { requestedScopes ->
            val intersection = requestedScopes.intersect(entity.scopes)
            if (intersection.isEmpty()) throw InvalidAuthorizeOrTokenParmsException(clientId)
        }
        return entity
    }

    fun createTokenAndStorePKCE(
        responseType: OAuth2ResponseType,
        clientId: String,
        redirectURI: String,
        challengeCode: String,
        challengeCodeMethod: CodeChallengeMethods,
        maxTokenTTLInSeconds: Int = 0,
        scopes: String? = null,
        nonce: String? = null,
        user: User? = null,
    ): OAuth2AuthorizationResponse {
        if (responseType != OAuth2ResponseType.CODE) throw OAuth2InvalidResponseTypeException()

        val entity = validateClientIdWithParameters(clientId, redirectURI, scopes)

        if (entity.user?.id != user?.id || entity.user?.pWordHash != user?.pWordHash)
            throw ClientInvalidException()

        // generate a random token
        val newAuthToken = tokenGenerator.generateRandomToken(16, CodeEncoding.HEX_LOWERCASE)
        val tokenValidity = maxOf(1, maxTokenTTLInSeconds).minutes

        val requestedScopes = (scopes?.split(" ")?.filterNot { it.isBlank() } ?: emptySet())
            .ifEmpty { entity.scopes }
        val clientScopes = requestedScopes intersect entity.scopes
        val clientScopesString = clientScopes.joinToString(" ")

        val authTokenModel = AuthorizeTokenModel(
            authCode = newAuthToken,
            redirectURI = redirectURI,
            scopes = clientScopesString,
            clientId = clientId,
        )

        val codeExchange = PKCEModel(challengeCode = challengeCode, challengeCodeMethod)

        // if it's an openid scope request, create a token too
        if ("openid" in clientScopes && nonce != null) {
            authCodeStore.saveClientNonce(clientId = entity.clientId, nonce = nonce, expiry = tokenValidity)
        }

        // save the token client and the challenge codes
        authCodeStore.saveAuthTokenInfo(model = authTokenModel, expiry = tokenValidity)
        challengesStore.saveClientPKCE(clientId = entity.clientId, pkCE = codeExchange, expiry = tokenValidity)

        // returns the newAuthToken
        return OAuth2AuthorizationResponse(
            authCode = newAuthToken,
            type = OAuth2ResponseType.CODE,
            redirect = redirectURI,
            expiresIn = tokenValidity.inWholeMilliseconds
        )
    }

    fun validateTokenRequest(
        clientId: String,
        authCode: String,
        redirect: String,
        clientSecret: String? = null,
        codeVerifier: String? = null,
        scopes: String? = null,
    ): OAuth2TokenResponseDto {

        // basic validation
        if (authCode.isBlank()) throw InvalidAuthorizeOrTokenParmsException("Code cannot be empty or blank ")

        //validate parameters
        val entity = validateClientIdWithParameters(clientId, redirect)

        val codeVerifierPresent = codeVerifier != null && codeVerifier.isNotBlank()
        val clientSecretPresent = clientSecret != null && clientSecret.isNotBlank()

        when {
            codeVerifierPresent && clientSecretPresent ->
                throw InvalidAuthorizeOrTokenParmsException("Request is ambiguous needed a single proof of authority")

            codeVerifierPresent && !clientSecretPresent -> {
                val codeExchange = challengesStore.getCodeChallenges(entity.clientId) ?: throw PKCEInvalidException()
                val isVerified = codeExchange.verifyHash(codeVerifier)
                if (!isVerified) throw PKCEInvalidException()
            }

            !codeVerifierPresent && clientSecretPresent -> {
                val codeExchange = challengesStore.getCodeChallenges(entity.clientId)
                if (codeExchange != null)
                    throw InvalidAuthorizeOrTokenParmsException("Client was authorized with a different proof")
                // hash the client secret and check if this is correct
                val secretHash = tokenGenerator.hashToken(clientSecret)
                if (entity.secretHash != secretHash) throw InvalidAuthorizeOrTokenParmsException(clientId)
            }

            else -> throw InvalidAuthorizeOrTokenParmsException("No proof of authority")
        }

        // check if the auth code matches
        val authModel = authCodeStore.findAuthCodeViaClient(clientId) ?: throw OAuth2AuthCodeFailedException()
        // validate the values
        val isAuthModelCorrect = authModel.authCode == authCode &&
                authModel.redirectURI == redirect &&
                authModel.clientId == clientId
        if (!isAuthModelCorrect) throw OAuth2AuthCodeFailedException()

        // check if the scopes are matching
        val requestedScopes = (scopes?.split(" ")?.filterNot { it.isBlank() } ?: emptySet())
            .ifEmpty { entity.scopes }
        val savedScopes = authModel.scopes?.split(" ") ?: emptySet()

        // union of the requested and saved one and the intersection of client scopes
        val possibleScopes = (requestedScopes union savedScopes) intersect (entity.scopes)
        if (possibleScopes.isEmpty()) throw InvalidAuthorizeOrTokenParmsException(clientId)

        val possibleScopesString = possibleScopes.joinToString(" ")

        try {
            // everything went well time to create a jwt
            val tokens = jwtTokenGenerator.generateOAuthTokenPair(
                user = entity.user,
                clientId = entity.clientId,
                scopes = possibleScopesString,
                createRefreshToken = entity.allowRefreshTokens
            )

            // get the id token info if available
            val idToken = entity.user?.let { user ->
                if (!possibleScopes.contains("openid")) return@let null
                createIdTokenForUser(
                    scopes = possibleScopes,
                    clientId = clientId,
                    user = user,
                    accessToken = tokens.accessToken
                )
            }

            return OAuth2TokenResponseDto(
                accessToken = tokens.accessToken,
                expiry = tokens.accessTokenExpireInMillis,
                oidcToken = idToken,
                refreshToken = if (entity.allowRefreshTokens) tokens.refreshToken else null,
                refreshTokenExpiry = if (entity.allowRefreshTokens) tokens.refreshTokenExpiresInMillis else 0L,
                redirectURI = redirect,
                scopes = possibleScopesString,
            )

        } finally {
            // ensures the code is cleaned
            challengesStore.deleteClientPKCE(clientId)
            authCodeStore.deleteCodeAndClient(clientId)
        }
    }

    fun createTokensForClientCredentialsGrant(
        clientId: String,
        clientSecret: String?,
        scopes: String? = null,
    ): OAuth2TokenResponseDto {
        if (clientSecret == null)
            throw InvalidAuthorizeOrTokenParmsException("Client Secret required for client")

        val entity = repository.findOAuth2ClientEntityByClientId(clientId)
            ?: throw ClientNotFoundException(clientId)

        // if no scopes are found, use the current scopes
        val requestedScopes = (scopes?.split(" ")?.filterNot { it.isBlank() } ?: emptySet())
            .ifEmpty { entity.scopes }
        // only take the scopes that are common to provided and existed
        val possibleScopes = requestedScopes intersect entity.scopes
        if (possibleScopes.isEmpty()) throw InvalidAuthorizeOrTokenParmsException("None of the scopes are valid to work with")


        val jwtScopes = possibleScopes.joinToString(" ")

        val tokens = jwtTokenGenerator.generateOAuthTokenPair(
            clientId = entity.clientId,
            scopes = jwtScopes,
            createRefreshToken = false,
            responseType = OAuth2GrantTypes.CLIENT_CREDENTIALS
        )

        return OAuth2TokenResponseDto(
            accessToken = tokens.accessToken,
            scopes = jwtScopes,
            expiry = tokens.accessTokenExpireInMillis,
            tokenType = "Bearer"
        )
    }

    @OptIn(ExperimentalTime::class)
    fun handleRefreshTokenGrant(
        clientId: String,
        token: String,
        clientSecret: String? = null,
        scopes: String? = null,
    ): OAuth2TokenResponseDto {

        // check if the token is already blacklisted
        if (blackListManager.isBlackListed(token, JWTTokenType.REFRESH_TOKEN))
            throw InvalidAuthorizeOrTokenParmsException("Cannot validate the given token")

        // validate the credentials
        val entity = repository.findOAuth2ClientEntityByClientId(clientId)
            ?: throw ClientNotFoundException(clientId)

        if (!entity.isValid) throw ClientInvalidException()

        // validate the client secret
        if (clientSecret != null) {
            val secretHash = tokenGenerator.hashToken(clientSecret)
            if (secretHash != entity.secretHash) throw ClientAuthFailedException()
        }

        // introspect the token
        val result = jwtTokenGenerator.introspectToken(token)
            ?: throw InvalidAuthorizeOrTokenParmsException("Cannot decode the token")

        // invalid token credentials
        if (result.clientId != clientId || result.userId != entity.user?.id) throw ClientInvalidException()

        // check if the scopes are matching
        val tokenScopes = result.scope.split(" ").filterNot { it.isBlank() }.toSet()
        val requestedScopes = (scopes?.split(" ")?.filterNot { it.isBlank() } ?: emptySet())
            .ifEmpty { entity.scopes }

        val finalScopes = if (requestedScopes.isNotEmpty()) {
            // common in requested , token scopes and the entity
            requestedScopes intersect tokenScopes intersect entity.scopes
        } else tokenScopes intersect entity.scopes

        val jwtScopes = finalScopes.joinToString(" ")

        try {
            // everything went well time to create a jwt
            val tokens = jwtTokenGenerator.generateOAuthTokenPair(
                user = entity.user,
                clientId = entity.clientId,
                scopes = jwtScopes,
                createRefreshToken = true
            )

            // get the id token info if available
            val idToken = entity.user?.let { user ->
                createIdTokenForUser(
                    scopes = finalScopes,
                    clientId = clientId,
                    user = user,
                    accessToken = tokens.accessToken
                )
            }

            return OAuth2TokenResponseDto(
                accessToken = tokens.accessToken,
                expiry = tokens.accessTokenExpireInMillis,
                oidcToken = idToken,
                refreshToken = if (entity.allowRefreshTokens) tokens.refreshToken else null,
                refreshTokenExpiry = if (entity.allowRefreshTokens) tokens.refreshTokenExpiresInMillis else 0L,
                redirectURI = null,
                scopes = jwtScopes,
            )

        } finally {
            // revoke the token
            val ttl = result.expiresAt.toKotlinInstant() - Clock.System.now()
            if (ttl.isPositive()) blackListManager.addToBlackList(token, JWTTokenType.REFRESH_TOKEN, ttl)
        }
    }

    private fun createIdTokenForUser(scopes: Set<String>, clientId: String, user: User, accessToken: String): String? {
        if (!scopes.contains("openid")) return null

        val savedNonce = authCodeStore.getClientNonce(clientId) ?: return null
        return oidcTokenGenerator.generateOIDCToken(
            user = user,
            clientId = clientId,
            nonce = savedNonce,
            includeEmail = scopes.contains("email"),
            includeProfile = scopes.contains("profile"),
            tokenHash = tokenGenerator.hashToken(accessToken),
            tokenExpiry = 1.hours
        )
    }
}