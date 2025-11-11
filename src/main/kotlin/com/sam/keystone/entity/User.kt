package com.sam.keystone.entity

import jakarta.persistence.*
import java.time.LocalDateTime


@Entity
@Table(name = "users_table")
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

    @Column(nullable = false, name = "created_at")
    val createdAt: LocalDateTime = LocalDateTime.now(),

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], fetch = FetchType.LAZY, optional = true)
    var profile: UserProfile? = null,
)
