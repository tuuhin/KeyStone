package com.sam.keystone.modules.user.entity

import jakarta.persistence.*

@Entity
@Table(name = "users_profile")
class UserProfile(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "profile_id", columnDefinition = "INTEGER")
    var id: Long? = null,

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    val user: User? = null,

    @Column(name = "bio", length = 512, nullable = true)
    var bio: String? = null,

    @Column(name = "display_name", nullable = true)
    var displayName: String? = null,

    @Column(name = "avatar_image_key", nullable = true)
    var imageKey: String? = null,
)