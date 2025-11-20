package com.sam.keystone.modules.user.entity

import jakarta.persistence.*

@Entity
@Table(name = "user_verify_info_table")
class UserVerifyInfo(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "_id", columnDefinition = "INTEGER")
    var id: Long? = null,

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    val user: User? = null,

    @Column(name = "is_verified", nullable = false)
    var isVerified: Boolean = false,

    @Column(name = "resend_email_key_hash", nullable = true)
    val resendKey: String? = null,

    @Column(name = "is_key_valid", nullable = false)
    var isKeyValid: Boolean = false,
)