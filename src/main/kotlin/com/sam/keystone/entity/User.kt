package com.sam.keystone.entity

import jakarta.persistence.*
import java.time.LocalDateTime


@Entity
@Table(
    name = "users_table",
    indexes = [Index(name = "user_name", unique = true, columnList = "user_name")]
)
class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    val id: Long = 0L,

    @Column(name = "email", nullable = false)
    val email: String,

    @Column(name = "p_word", nullable = false)
    val pWordHash: String,

    @Column(name = "user_name", nullable = false, unique = true)
    val userName: String,

    @Column(name = "created_at", nullable = false)
    val createdAt: LocalDateTime = LocalDateTime.now(),

    @Column(name = "is_verified", nullable = false)
    var isVerified: Boolean = false,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], fetch = FetchType.LAZY, optional = true)
    var profile: UserProfile? = null,
)
