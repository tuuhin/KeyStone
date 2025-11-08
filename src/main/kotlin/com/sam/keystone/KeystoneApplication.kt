package com.sam.keystone

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KeystoneApplication

fun main(args: Array<String>) {
	runApplication<KeystoneApplication>(*args)
}
