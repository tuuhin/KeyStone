package com.sam.keystone.modules.oauth2.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.jwt.OAuth2JWTTokenGeneratorService
import com.sam.keystone.infrastructure.jwt.OIDCJWTTokenGenerator
import com.sam.keystone.infrastructure.redis.OAuth2AuthCodeStore
import com.sam.keystone.infrastructure.redis.OAuth2CodePKCEStore
import com.sam.keystone.modules.oauth2.dto.OAuth2AuthorizationResponse
import com.sam.keystone.modules.oauth2.dto.OAuth2TokenResponseDto
import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.oauth2.exceptions.*
import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import com.sam.keystone.modules.oauth2.repository.OAuth2ClientRepository
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.security.models.AuthorizeTokenModel
import com.sam.keystone.security.models.CodeChallengeMethods
import com.sam.keystone.security.models.PKCEModel
import org.springframework.stereotype.Service
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

@Service
class OAuth2AuthService(
    private val repository: OAuth2ClientRepository,
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val challengesStore: OAuth2CodePKCEStore,
    private val authCodeStore: OAuth2AuthCodeStore,
    private val jwtTokenGenerator: OAuth2JWTTokenGeneratorService,
    private val oidcTokenGenerator: OIDCJWTTokenGenerator,
) {

    private fun validateRequestParameters(
        clientId: String,
        redirectURI: String,
        scope: String? = null,
        grantType: String? = null,
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

        // check for grant types
        grantType?.split(" ")?.let { types ->
            val intersection = types.intersect(entity.grantTypes)
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
        scope: String? = null,
        grantType: String? = null,
        nonce: String? = null,
    ): OAuth2AuthorizationResponse {
        if (responseType != OAuth2ResponseType.CODE) throw OAuth2InvalidResponseTypeException()

        val entity = validateRequestParameters(clientId, redirectURI, scope, grantType)

        // generate a random token
        val newAuthToken = tokenGenerator.generateRandomToken(16, CodeEncoding.HEX_LOWERCASE)
        val tokenValidity = 2.minutes

        val authTokenModel = AuthorizeTokenModel(
            authCode = newAuthToken,
            redirectURI = redirectURI,
            scopes = scope,
            clientId = clientId,
            grantType = grantType
        )

        val codeExchange = PKCEModel(challengeCode = challengeCode, challengeCodeMethod)

        // if it's an openid scope request, create a token too
        val providedScopes = scope?.split(" ") ?: emptySet()
        if ("openid" in providedScopes && nonce != null) {
            authCodeStore.saveClientNonce(clientId = entity.clientId, nonce = nonce, expiry = 2.minutes)
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
        clientSecret: String,
        redirect: String,
        grantType: String,
        authCode: String,
        codeVerifier: String,
    ): OAuth2TokenResponseDto {
        // validate the grant type
        if (grantType != "authorization_code") throw InvalidAuthorizeOrTokenParmsException(clientId)

        //validate parameters
        val entity = validateRequestParameters(clientId, redirect)
        val user = entity.user ?: throw InvalidAuthorizeOrTokenParmsException(clientId)

        // hash the client secret and check if this is correct
        val secretHash = tokenGenerator.hashToken(clientSecret)
        if (entity.secretHash != secretHash) throw InvalidAuthorizeOrTokenParmsException(clientId)

        // check if the hash matches
        val codeExchange = challengesStore.getCodeChallenges(entity.clientId) ?: throw PKCEInvalidException()
        val isVerified = codeExchange.verifyHash(codeVerifier)
        if (!isVerified) throw PKCEInvalidException()

        // check if the auth code matches
        val authModel = authCodeStore.findAuthCodeViaClient(clientId) ?: throw OAuth2AuthCodeFailedException()

        if (authModel.authCode != authCode) throw OAuth2AuthCodeFailedException()
        if (authModel.redirectURI != redirect) throw InvalidAuthorizeOrTokenParmsException(clientId)

        // check if the scopes are matching
        val requestedScopes = authModel.scopes?.split(" ") ?: emptySet()
        val possibleScopes = requestedScopes.intersect(entity.scopes)
        if (possibleScopes.isEmpty()) throw InvalidAuthorizeOrTokenParmsException(clientId)

        val accessTokenTTL = 15.minutes
        val refreshTokenTTL = 1.days

        val jwtScopes = possibleScopes.joinToString(" ")

        // everything went well time to create a jwt
        val tokens = jwtTokenGenerator.generateOAuthTokenPair(
            user = user,
            clientId = entity.clientId,
            scopes = jwtScopes,
            accessTokenExpiry = accessTokenTTL,
            refreshTokenExpiry = refreshTokenTTL
        )

        try {
            // get the id token info if available
            val idToken = createIdTokenForUser(
                scopes = possibleScopes,
                clientId = clientId,
                user = user,
                accessToken = tokens.accessToken
            )

            return OAuth2TokenResponseDto(
                accessToken = tokens.accessToken,
                expiry = accessTokenTTL.inWholeMilliseconds,
                oidcToken = idToken,
                refreshToken = if (entity.allowRefreshTokens) tokens.refreshToken else null,
                refreshTokenExpiry = if (entity.allowRefreshTokens) refreshTokenTTL.inWholeMilliseconds else 0L,
                redirectURI = redirect,
                scopes = jwtScopes,
            )

        } finally {
            // ensures the code is cleaned
            challengesStore.deleteClientPKCE(clientId)
            authCodeStore.deleteCodeAndClient(clientId)
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