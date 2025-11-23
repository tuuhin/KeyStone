package com.sam.keystone.modules.user.convertors

import com.sam.keystone.modules.user.models.JWTTokenType
import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component


@Component
class JWTTokenEnumConvertor : Converter<String, JWTTokenType> {
    override fun convert(source: String): JWTTokenType {
        return JWTTokenType.entries.find { it.simpleName == source }
            ?: throw IllegalArgumentException("Invalid code convertor")
    }
}