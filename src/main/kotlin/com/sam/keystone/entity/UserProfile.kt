package com.sam.keystone.entity

import jakarta.persistence.*

@Entity
@Table(name = "users_profile")
class UserProfile(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "profile_id")
    val id: Long = 0L,

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    val user: User,

    @Column(name = "bio", length = 512, nullable = true)
    var bio: String? = null,

    @Column(name = "full_name", nullable = true)
    var fullName: String? = null,

    @Column(name = "avatar_url", nullable = true)
    var avatarUrl: String? = null,
)