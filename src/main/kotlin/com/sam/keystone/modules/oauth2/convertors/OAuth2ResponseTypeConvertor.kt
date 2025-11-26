package com.sam.keystone.modules.oauth2.convertors

import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component

@Component
class OAuth2ResponseTypeConvertor : Converter<String, OAuth2ResponseType> {
    override fun convert(source: String): OAuth2ResponseType? {
        return OAuth2ResponseType.entries.find { it.simpleName == source }
            ?: throw IllegalArgumentException("Invalid type")
    }
}