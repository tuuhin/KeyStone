package com.sam.keystone.infrastructure.oidc

import com.fasterxml.jackson.annotation.JsonProperty

data class OIDCConfigurationDto(
    val issuer: String,
    @field:JsonProperty("authorization_endpoint")
    val authorizationEndpoint: String,
    @field:JsonProperty("token_endpoint")
    val tokenEndpoint: String,
    @field:JsonProperty("userinfo_endpoint")
    val userinfoEndpoint: String,
    @field:JsonProperty("jwks_uri")
    val jWKSEndpoint: String,
    @field:JsonProperty("scopes_supported")
    val supportedScopes: List<String> = emptyList(),
    @field:JsonProperty("response_types_supported")
    val responseType: List<String> = emptyList(),
    @field:JsonProperty("grant_types_supported")
    val supportedGrantType: List<String> = emptyList(),
    @field:JsonProperty("subject_types_supported")
    val supportedSubjectType: List<String> = emptyList(),
    @field:JsonProperty("id_token_signing_alg_values_supported")
    val algorithm: List<String> = emptyList(),
)
