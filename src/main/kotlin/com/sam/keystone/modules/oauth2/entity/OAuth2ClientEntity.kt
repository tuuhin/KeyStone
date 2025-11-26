package com.sam.keystone.modules.oauth2.entity

import com.sam.keystone.modules.user.entity.User
import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "oauth_2_client_table")
class OAuth2ClientEntity(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "_id", columnDefinition = "INTEGER")
    val id: Int? = null,

    @Column(name = "client_id", unique = true, nullable = false)
    val clientId: String = "",

    @Column(name = "client_secret_hash", nullable = true)
    var secretHash: String? = null,

    @Column(name = "client_name")
    var clientName: String = "",

    @ManyToOne(fetch = FetchType.LAZY, targetEntity = User::class, optional = false)
    @JoinColumn(name = "user_id")
    val user: User? = null,

    @Column(name = "is_valid")
    val isValid: Boolean = true,

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth_2_client_redirect_uris_table",
        joinColumns = [JoinColumn(name = "client_id", referencedColumnName = "client_id")]
    )
    @Column(name = "redirects")
    val redirectUris: MutableSet<String> = mutableSetOf(),

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth_2_client_scopes_table",
        joinColumns = [JoinColumn(name = "client_id", referencedColumnName = "client_id")]
    )
    @Column(name = "scope")
    val scopes: MutableSet<String> = mutableSetOf(),

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth_2_client_grant_types_table",
        joinColumns = [JoinColumn(name = "client_id", referencedColumnName = "client_id")]
    )
    @Column(name = "grant_type")
    val grantTypes: MutableSet<String> = mutableSetOf(),

    @Column(name = "created_at")
    val createdAt: Instant = Instant.now(),

    @Column(name = "updated_at")
    var updatedAt: Instant = Instant.now(),

    @Column(name = "allow_refresh_tokens")
    val allowRefreshTokens: Boolean = false,
) {

    @PreUpdate
    fun onUpdate() {
        updatedAt = Instant.now()
    }
}