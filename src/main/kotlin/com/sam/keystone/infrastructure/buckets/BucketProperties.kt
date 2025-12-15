package com.sam.keystone.infrastructure.buckets

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding

@ConfigurationProperties(prefix = "aws.s3")
data class BucketProperties @ConstructorBinding constructor(
    val bucketName: String,
)