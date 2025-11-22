package com.sam.keystone.modules.oauth2.convertors

import com.sam.keystone.modules.oauth2.models.CodeChallengeMethods
import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component

@Component
class CodeChallengeEnumConvertor : Converter<String, CodeChallengeMethods> {
    override fun convert(source: String): CodeChallengeMethods {
        return CodeChallengeMethods.entries.find { it.simpleName == source }
            ?: throw IllegalArgumentException("Invalid code convertor")
    }
}