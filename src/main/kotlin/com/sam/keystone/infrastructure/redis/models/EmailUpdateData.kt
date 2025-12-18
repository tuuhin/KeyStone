package com.sam.keystone.infrastructure.redis.models

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

data class EmailUpdateData @JsonCreator(mode = JsonCreator.Mode.PROPERTIES) constructor(
    @field:JsonProperty("user_id") val userId: Long,
    @field:JsonProperty("meta") val meta: String? = null,
) : Serializable