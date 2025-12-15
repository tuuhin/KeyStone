package com.sam.keystone.infrastructure.buckets

import io.awspring.cloud.s3.ObjectMetadata
import io.awspring.cloud.s3.S3Template
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import java.io.File
import java.util.concurrent.CompletableFuture
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class S3StorageBucket(
    private val template: S3Template,
    private val properties: BucketProperties,
) {

    @Async
    fun uploadFile(key: String, file: File, contentType: String?): CompletableFuture<String> {
        val stream = file.inputStream()
        val resource = stream.use { stream ->
            val metaData = ObjectMetadata.builder()
                .contentType(contentType)
                .build()
            // blocking
            template.upload(properties.bucketName, key, stream, metaData)
        }
        return CompletableFuture.completedFuture(resource.filename)
    }

    @Async
    fun deleteFile(key: String) {
        // blocking
        template.deleteObject(properties.bucketName, key)
    }

    fun provideSignedURL(key: String, ttl: Duration = 5.minutes): String {
        return template.createSignedGetURL(properties.bucketName, key, ttl.toJavaDuration()).toString()
    }
}