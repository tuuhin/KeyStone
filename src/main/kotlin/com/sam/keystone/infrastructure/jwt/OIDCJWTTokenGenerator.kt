package com.sam.keystone.infrastructure.jwt

import com.sam.keystone.modules.user.entity.User
import org.springframework.stereotype.Component
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

@Component
class OIDCJWTTokenGenerator(private val generator: JWTKeysGenerator) {

    fun generateOIDCToken(
        user: User,
        clientId: String,
        nonce: String,
        tokenHash: String,
        includeEmail: Boolean = false,
        includeProfile: Boolean = false,
        tokenExpiry: Duration = 2.hours,
    ): String {

        val baseMap = buildMap {
            put(JWTClaims.JWT_CLAIM_SUB, user.id)
            put(JWTClaims.JWT_CLAIM_AUDIENCE, clientId)
            put(JWTClaims.JWT_CLAIM_NONCE, nonce)
            put(JWTClaims.JWT_TOKEN_AT_HASH, tokenHash)
            if (includeEmail) {
                put(JWTClaims.JWT_OPEN_ID_CLAIM_EMAIL, user.email)
                put(JWTClaims.JWT_OPEN_ID_CLAIM_EMAIL_VERIFIED, (user.verifyState?.isVerified ?: false))
            }
            if (includeProfile) {
                put(JWTClaims.JWT_OPEN_ID_CLAIM_USER_NAME, user.userName)
                put(JWTClaims.JWT_OPEN_ID_CLAIM_USER_AVATAR, user.profile?.avatarUrl)
                put(JWTClaims.JWT_OPEN_ID_CLAIM_USER_FULL_NAME, user.profile?.fullName)
            }
        }

        return generator.generateToken(
            timeToLive = tokenExpiry,
            claims = baseMap
        )
    }
}