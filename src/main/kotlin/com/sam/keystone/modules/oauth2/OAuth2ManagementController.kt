package com.sam.keystone.modules.oauth2

import com.sam.keystone.modules.core.dto.ErrorResponseDto
import com.sam.keystone.modules.core.dto.MessageResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientListResponseDto
import com.sam.keystone.modules.oauth2.dto.OAuth2ClientResponseDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientRequestDto
import com.sam.keystone.modules.oauth2.dto.RegisterClientResponseDto
import com.sam.keystone.modules.oauth2.services.OAuth2ClientService
import com.sam.keystone.modules.user.utils.ext.currentUser
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/oauth2/clients")
@Tag(
    name = "OAuth2 Client Management",
    description = "Manges crud operation associated with client"
)
@SecurityRequirement(name = "Authorization")
class OAuth2ManagementController(
    private val service: OAuth2ClientService,
) {

    @PostMapping("/create")
    @Operation(summary = "Register a new OAuth client")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "201",
                description = "OAuth client created in association with the given user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(RegisterClientResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun registerClient(@RequestBody request: RegisterClientRequestDto): ResponseEntity<RegisterClientResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val clientResponse = service.createNewClient(request, currentUser)
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(clientResponse)
    }

    @GetMapping("/")
    @Operation(summary = "List all the register clients with the associated user")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "List clients register by the user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2ClientListResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun listAllClients(): ResponseEntity<OAuth2ClientListResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val clientResponse = service.fetchAllClientsAssociatedToUser(currentUser)
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(clientResponse)
    }

    @GetMapping("/{clientId}")
    @Operation(summary = "Fetch a particular client")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Client Details",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2ClientResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid Client Id",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun clientDetails(@PathVariable clientId: String): ResponseEntity<OAuth2ClientResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val clientResponse = service.fetchClientWithClientIdAndUser(clientId, currentUser)
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(clientResponse)
    }


    @DeleteMapping("/{clientId}")
    @Operation(summary = "Delete the created client")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "202",
                description = "Delete Request Accepted",
                content = [
                    Content(mediaType = "application/json", schema = Schema(MessageResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid Client Id",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun deleteClient(@PathVariable clientId: String): ResponseEntity<MessageResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val response = service.deleteClient(clientId, currentUser)

        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .body(response)
    }


    @PostMapping("/{clientId}/regenerate_secret")
    @Operation(summary = "Regenerate a new client secret discarding the previous one")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "201",
                description = "New secret created",
                content = [
                    Content(mediaType = "application/json", schema = Schema(RegisterClientResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid Client Id",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun regenerateNewSecret(@PathVariable clientId: String): ResponseEntity<RegisterClientResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val response = service.regenerateClientSecret(clientId, currentUser)
        return ResponseEntity.status(HttpStatus.CREATED).body(response)
    }

    @PutMapping("/{clientId}")
    @Operation(summary = "Update the metadata for the client")
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "202",
                description = "New metadata is accepted",
                content = [
                    Content(mediaType = "application/json", schema = Schema(OAuth2ClientResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "400",
                description = "Invalid Client Id",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
            ApiResponse(
                responseCode = "403",
                description = "Unauthenticated user",
                content = [
                    Content(mediaType = "application/json", schema = Schema(implementation = ErrorResponseDto::class)),
                ]
            ),
        ]
    )
    fun updateClientInformation(
        @PathVariable clientId: String,
        @RequestBody request: RegisterClientRequestDto,
    ): ResponseEntity<OAuth2ClientResponseDto> {
        val currentUser = SecurityContextHolder.getContext().authentication.currentUser
        val response = service.updateClientMetaData(clientId, currentUser, request)
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response)
    }
}