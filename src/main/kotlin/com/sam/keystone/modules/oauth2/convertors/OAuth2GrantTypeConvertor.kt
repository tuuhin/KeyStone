package com.sam.keystone.modules.oauth2.convertors

import com.sam.keystone.modules.oauth2.models.OAuth2GrantTypes
import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component

@Component
class OAuth2GrantTypeConvertor : Converter<String, OAuth2GrantTypes> {
    override fun convert(source: String): OAuth2GrantTypes? {
        return OAuth2GrantTypes.entries.find { it.value == source }
            ?: throw IllegalArgumentException("Invalid type")
    }
}