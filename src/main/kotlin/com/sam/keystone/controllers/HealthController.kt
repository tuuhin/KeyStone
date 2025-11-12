package com.sam.keystone.controllers

import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RestController
@RequestMapping("/health")
@Tag(name = "Health")
class HealthController {


    @GetMapping
    @Operation(summary = "A indication that the server is working")
    fun healthStatus() = mapOf("status" to "Ok")
}