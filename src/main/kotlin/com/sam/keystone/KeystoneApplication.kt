package com.sam.keystone

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableAsync

@EnableAsync
@ConfigurationPropertiesScan
@SpringBootApplication
class KeystoneApplication

fun main(args: Array<String>) {
    runApplication<KeystoneApplication>(*args)
}
