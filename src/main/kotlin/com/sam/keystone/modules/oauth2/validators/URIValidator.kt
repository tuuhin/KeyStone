package com.sam.keystone.modules.oauth2.validators

import java.net.MalformedURLException
import java.net.URL

object URIValidator {

    fun isValid(value: String): Boolean {
        if (value.isBlank()) return false
        try {
            val url = URL(value)
            val scheme = url.protocol.lowercase()
            if (scheme != "http" && scheme != "https") return false
            if (url.host.isNullOrBlank()) return false
            return true
        } catch (_: MalformedURLException) {
            return false
        } catch (_: Exception) {
            return false
        }
    }
}