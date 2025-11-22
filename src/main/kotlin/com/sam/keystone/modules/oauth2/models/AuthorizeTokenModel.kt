package com.sam.keystone.modules.oauth2.models

data class AuthorizeTokenModel(
    val code: String,
    val redirectURI: String,
    val clientId: String,
    val scopes: String? = null,
    val grantType: String? = null,
)
