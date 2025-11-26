package com.sam.keystone.security.models

import com.auth0.jwt.interfaces.Claim
import com.sam.keystone.security.exception.OAuth2ClientIDNotAttachedException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.user.OAuth2User

data class OAuth2ClientUser(
    private val username: String?,
    private val claims: Map<String, Claim> = emptyMap(),
    val scopes: Set<String> = emptySet(),
) : OAuth2User {

    override fun getAttributes(): Map<String, Any?> = claims

    override fun getAuthorities(): Collection<GrantedAuthority?> =
        scopes.map { SimpleGrantedAuthority("SCOPE_$it") }

    override fun getName(): String? = username

    val clientId: String
        get() = claims.getOrDefault("oauth2_client_id", null)?.asString()
            ?: throw OAuth2ClientIDNotAttachedException()

    val userId: Long?
        get() = claims.getOrDefault("user_id", null)?.asLong()
}