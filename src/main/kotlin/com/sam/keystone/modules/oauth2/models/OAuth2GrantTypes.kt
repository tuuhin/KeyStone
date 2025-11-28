package com.sam.keystone.modules.oauth2.models

enum class OAuth2GrantTypes(val value: String) {
    AUTHORIZATION_CODE("authorization_code"),
    CLIENT_CREDENTIALS("client_credentials"),
    REFRESH_TOKEN("refresh_token");

    companion object {
        val grants = OAuth2GrantTypes.entries.map { it.value }.toSet()
    }
}