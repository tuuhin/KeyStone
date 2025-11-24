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
            put(JWT_OPEN_ID_CLAIM_SUB, user.id)
            put(JWT_OPEN_ID_CLAIM_AUDIENCE, clientId)
            put(JWT_OPEN_ID_CLAIM_NONCE, nonce)
            put(JWT_OPEN_ID_CLAIM_AT_HASH, tokenHash)
            if (includeEmail) {
                put(JWT_OPEN_ID_CLAIM_EMAIL, user.email)
                put(JWT_OPEN_ID_CLAIM_EMAIL_VERIFIED, (user.verifyState?.isVerified ?: false))
            }
            if (includeProfile) {
                put(JWT_OPEN_ID_CLAIM_USER_NAME, user.userName)
                put(JWT_OPEN_ID_CLAIM_USER_AVATAR, user.profile?.avatarUrl)
                put(JWT_OPEN_ID_CLAIM_USER_FULL_NAME, user.profile?.fullName)
            }
        }

        return generator.generateToken(
            timeToLive = tokenExpiry,
            claims = baseMap
        )
    }

    companion object {
        private const val JWT_OPEN_ID_CLAIM_SUB = "sub"
        private const val JWT_OPEN_ID_CLAIM_AUDIENCE = "aud"
        private const val JWT_OPEN_ID_CLAIM_NONCE = "nonce"
        private const val JWT_OPEN_ID_CLAIM_AT_HASH = "at_hash"
        private const val JWT_OPEN_ID_CLAIM_EMAIL = "email"
        private const val JWT_OPEN_ID_CLAIM_EMAIL_VERIFIED = "email_verified"
        private const val JWT_OPEN_ID_CLAIM_USER_NAME = "user_name"
        private const val JWT_OPEN_ID_CLAIM_USER_AVATAR = "user_avatar"
        private const val JWT_OPEN_ID_CLAIM_USER_FULL_NAME = "user_full_name"
    }
}