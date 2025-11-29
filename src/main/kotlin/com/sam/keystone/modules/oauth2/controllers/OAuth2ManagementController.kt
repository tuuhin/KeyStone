package com.sam.keystone.modules.oauth2.controllers

import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientListResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientResponseDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientRequestDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientResponseDto
import com.sam.keystone.modules.oauth2.services.OAuth2ClientService
import com.sam.keystone.modules.user.entity.User
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/oauth2/clients")
@Tag(
    name = "OAuth2 Client Management",
    description = "Manges crud operation associated with client"
)
@SecurityRequirement(name = "Authorization")
class OAuth2ManagementController(
    private val service: OAuth2ClientService,
) {

    @PostMapping("/create", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Register a new OAuth client")
    @ResponseStatus(HttpStatus.CREATED)
    fun registerClient(
        @Valid
        @RequestBody request: RegisterClientRequestDto,
        @AuthenticationPrincipal currentUser: User,
    ): RegisterClientResponseDto {
        return service.createNewClient(request, currentUser)
    }


    @GetMapping("/", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "List all the register clients with the associated user")
    fun listAllClients(@AuthenticationPrincipal currentUser: User): OAuth2ClientListResponseDto {
        return service.fetchAllClientsAssociatedToUser(currentUser)
    }


    @GetMapping("/{clientId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Fetch a particular client")
    fun clientDetails(
        @PathVariable clientId: String,
        @AuthenticationPrincipal currentUser: User,
    ): OAuth2ClientResponseDto {
        return service.fetchClientWithClientIdAndUser(clientId, currentUser)
    }


    @DeleteMapping("/{clientId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Delete the created client")
    fun deleteClient(@PathVariable clientId: String, @AuthenticationPrincipal currentUser: User): MessageResponseDto {
        return service.deleteClient(clientId, currentUser)
    }


    @PostMapping("/{clientId}/regenerate_secret", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Regenerate a new client secret discarding the previous one")
    fun regenerateNewSecret(
        @PathVariable clientId: String,
        @AuthenticationPrincipal currentUser: User,
    ): RegisterClientResponseDto {
        return service.regenerateClientSecret(clientId, currentUser)
    }


    @PutMapping("/{clientId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    @Operation(summary = "Update the metadata for the client")
    fun updateClientInformation(
        @PathVariable clientId: String,
        @RequestBody request: RegisterClientRequestDto,
        @AuthenticationPrincipal currentUser: User,
    ): OAuth2ClientResponseDto {
        return service.updateClientMetaData(clientId, currentUser, request)
    }
}