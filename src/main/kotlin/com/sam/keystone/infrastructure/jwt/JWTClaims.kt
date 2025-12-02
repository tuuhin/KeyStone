package com.sam.keystone.infrastructure.jwt

object JWTClaims {

    const val JWT_CLAIM_SUB = "sub"
    const val JWT_CLAIM_AUDIENCE = "aud"

    const val JWT_CLAIM_CLIENT_ID = "client_id"
    const val JWT_CLAIM_CLIENT_SCOPES = "scopes"
    const val JWT_CLAIM_USER_ID = "user_id"
    const val JWT_CLAIM_TOKEN_TYPE = "token_type"
    const val JWT_CLAIM_USER_NAME = "user_name"

    const val JWT_CLAIM_NONCE = "nonce"
    const val JWT_TOKEN_AT_HASH = "at_hash"

    // openid specific
    const val JWT_OPEN_ID_CLAIM_EMAIL = "email"
    const val JWT_OPEN_ID_CLAIM_EMAIL_VERIFIED = "email_verified"
    const val JWT_OPEN_ID_CLAIM_USER_AVATAR = "user_avatar"
    const val JWT_OPEN_ID_CLAIM_USER_FULL_NAME = "user_full_name"
}