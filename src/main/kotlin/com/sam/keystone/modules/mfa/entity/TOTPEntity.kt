package com.sam.keystone.modules.mfa.entity

import com.sam.keystone.modules.user.entity.User
import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "totp_table")
class TOTPEntity(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "totp_id", columnDefinition = "INTEGER")
    var id: Long = 0L,

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    val user: User? = null,

    @Column(name = "is_totp_enabled", nullable = false)
    var isEnabled: Boolean = false,

    // storing the totp secret as base 32 encoded
    @Column(name = "totp_secret_encrypted", nullable = false)
    var totpSecret: String = "",

    @OneToMany(
        fetch = FetchType.LAZY,
        mappedBy = "totp",
        cascade = [CascadeType.ALL],
        orphanRemoval = true
    )
    val backupCodes: Set<TOTPBackupCodesEntity> = emptySet(),

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
) {

    @PrePersist
    fun onCreate() {
        createdAt = Instant.now()
        updatedAt = createdAt
    }

    @PreUpdate
    fun onUpdate() {
        updatedAt = Instant.now()
    }
}