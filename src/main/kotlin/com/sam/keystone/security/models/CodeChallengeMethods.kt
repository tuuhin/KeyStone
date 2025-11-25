package com.sam.keystone.security.models

enum class CodeChallengeMethods(val simpleName: String) {
    PLAIN("plain"),
    SHA_256("sha256");


    companion object {
        fun fromString(algo: String): CodeChallengeMethods =
            CodeChallengeMethods.entries.find { it.simpleName == algo } ?: PLAIN
    }
}