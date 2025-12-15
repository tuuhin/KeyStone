package com.sam.keystone.modules.user.entity

import com.sam.keystone.modules.mfa.entity.TOTPEntity
import com.sam.keystone.modules.user.models.UserRole
import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.time.Instant


@Entity
@Table(
    name = "users_table",
    indexes = [Index(name = "user_name", unique = true, columnList = "user_name")]
)
class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", columnDefinition = "INTEGER")
    var id: Long = 0L,

    @Column(name = "email", nullable = false)
    val email: String = "",

    @Column(name = "p_word", nullable = false)
    var pWordHash: String = "",

    @Column(name = "user_name", nullable = false, unique = true)
    var userName: String = "",

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),

    @Column(name = "role", nullable = false)
    @Enumerated(value = EnumType.STRING)
    val role: UserRole = UserRole.USER,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], optional = false)
    var profile: UserProfile? = null,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], optional = false)
    var verifyState: UserVerifyInfo? = null,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], optional = true, fetch = FetchType.LAZY)
    var totpState: TOTPEntity? = null,

    @Column(name = "token_version", nullable = false, columnDefinition = "INTEGER")
    var tokenVersion: Int = 0,

    ) : UserDetails {

    @PrePersist
    fun onCreate() {
        createdAt = Instant.now()
    }

    @PreUpdate
    fun onUpdate() {
        updatedAt = Instant.now()
    }

    override fun getAuthorities(): Collection<GrantedAuthority?> = listOf(SimpleGrantedAuthority(role.name))

    override fun getPassword(): String? = null

    override fun getUsername(): String? = userName
}
