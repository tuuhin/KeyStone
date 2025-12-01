package com.sam.keystone.modules.oauth2.controllers

import com.sam.keystone.modules.oauth2.models.OAuth2ResponseType
import com.sam.keystone.modules.oauth2.services.OAuth2AuthService
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.security.models.CodeChallengeMethods
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

@Controller
@RequestMapping("/oauth2")
class OAuth2AuthorizeController(
    private val authService: OAuth2AuthService,
) {

    @GetMapping("/authorize")
    fun authorizeClient(

        @RequestParam("response_type", required = true)
        responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        @RequestParam("client_id", required = true)
        clientId: String,
        @RequestParam("redirect_uri", required = true)
        redirectUri: String,
        @RequestParam("scope", required = false)
        scope: String? = null,
        @RequestParam("max_age", required = false)
        maxAge: Int = 120,
        @RequestParam(value = "code_challenge", required = false)
        codeChallenge: String? = null,
        @RequestParam(value = "code_challenge_method", required = true)
        codeChallengeMethod: CodeChallengeMethods = CodeChallengeMethods.SHA_256,
        @RequestParam(value = "state", required = true)
        state: String,
        @RequestParam(value = "nonce", required = false)
        nonce: String? = null,
        // required
        @AuthenticationPrincipal user: User? = null,
        model: Model,
        request: HttpServletRequest,
    ): String? {

        // redirect the user if not logged in
        if (user == null) return "redirect:/login"

        // validate the given credentials
        val client = authService.validateClientIdWithParameters(clientId, redirectUri, scope)

        // validate the current client
        if (client.user?.id != user.id) return "redirect:/login"

        val requestedScopes = (scope?.split(" ")?.toSet() ?: emptySet()) union client.scopes
        val requestedScopesString = requestedScopes.joinToString(" ")

        model.addAttribute("client_name", client.clientName)
        model.addAttribute("client_id", clientId)
        model.addAttribute("redirect_uri", redirectUri)
        model.addAttribute("state", state)
        model.addAttribute("scopes_list", requestedScopes)
        model.addAttribute("scopes", requestedScopesString)
        model.addAttribute("max_age", maxAge)
        model.addAttribute("code_challenge_method", codeChallengeMethod.simpleName)
        model.addAttribute("code_challenge", codeChallenge)
        model.addAttribute("nonce", nonce)
        model.addAttribute("response_type", responseType.simpleName)
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        return "oauth_authorize"
    }

    @PostMapping(
        "/authorize",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE]
    )
    fun authorizePostRequest(
        @RequestParam("response_type", required = true)
        responseType: OAuth2ResponseType = OAuth2ResponseType.CODE,
        @RequestParam("client_id", required = true)
        clientId: String,
        @RequestParam("redirect_uri", required = true)
        redirectUri: String,
        @RequestParam(value = "code_challenge", required = true)
        codeChallenge: String? = null,
        @RequestParam(value = "code_challenge_method", required = true)
        codeChallengeMethod: CodeChallengeMethods = CodeChallengeMethods.SHA_256,
        @RequestParam(value = "state", required = true)
        state: String,
        @RequestParam("scope", required = false)
        scope: String? = null,
        @RequestParam("max_age")
        maxAge: Int = 5,
        @RequestParam(value = "nonce", required = false)
        nonce: String? = null,
        @RequestParam(value = "decision")
        isAllowed: Boolean = false,

        @AuthenticationPrincipal user: User,
    ): String {
        val resultURIBuilder = UriComponentsBuilder.fromUri(URI(redirectUri))
        try {
            //create the token
            val response = authService.createTokenAndStorePKCEIfProvided(
                responseType = responseType,
                clientId = clientId,
                redirectURI = redirectUri,
                scopes = scope,
                maxTokenTTLInSeconds = maxAge,
                challengeCode = codeChallenge,
                challengeCodeMethod = codeChallengeMethod,
                nonce = nonce,
                user = user
            )

            if (isAllowed) {
                resultURIBuilder.queryParam("code", response.authCode)
                resultURIBuilder.queryParam("state", state)
            } else {
                resultURIBuilder.queryParam("error", "access_denied")
                resultURIBuilder.queryParam("error_message", "Client authorization rejected")
            }

        } catch (e: Exception) {
            resultURIBuilder.queryParam("error", "access_denied")
            resultURIBuilder.queryParam("error_message", e.message)
        }

        val finalURI = resultURIBuilder.build()
        return "redirect:$finalURI"
    }
}