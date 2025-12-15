package com.sam.keystone.modules.mfa.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "totp_backup_codes_table")
class TOTPBackupCodesEntity(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "totp_backups_id", columnDefinition = "INTEGER")
    var id: Long = 0L,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "totp_id", nullable = false, unique = false)
    val totp: TOTPEntity? = null,

    @Column(name = "is_used", nullable = false)
    var isUsed: Boolean = false,

    @Column(name = "totp_backup_code_hash", nullable = false)
    val backUpCode: String,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)