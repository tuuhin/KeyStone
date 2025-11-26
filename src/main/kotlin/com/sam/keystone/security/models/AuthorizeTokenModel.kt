package com.sam.keystone.security.models

data class AuthorizeTokenModel(
    val authCode: String,
    val redirectURI: String,
    val clientId: String,
    val scopes: String? = null,
    val grantType: String? = null,
)
