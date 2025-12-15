package com.sam.keystone.modules.mfa.controllers

import com.sam.keystone.modules.mfa.dto.VerifyLoginRequestDto
import com.sam.keystone.modules.mfa.exceptions.MFAInvalidLoginChallengeException
import com.sam.keystone.modules.mfa.exceptions.MFANotEnabledException
import com.sam.keystone.modules.mfa.exceptions.TOTPCodeInvalidException
import com.sam.keystone.modules.mfa.services.MFAVerifyLoginService
import com.sam.keystone.security.utils.setCookieExt
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.servlet.mvc.support.RedirectAttributes

@Controller
class WebMFAuthController(
    private val mfaLoginService: MFAVerifyLoginService,
) {

    @GetMapping("verify-login")
    fun verifyLoginScreen(
        request: HttpServletRequest,
        model: Model,
        @RequestParam("mfa_token") token: String = "",
    ): String {
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        model.addAttribute("mfa_token", token)
        return "verify_login"
    }

    @PostMapping("verify-login", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun verifyLogin(
        request: HttpServletRequest,
        response: HttpServletResponse,
        redirect: RedirectAttributes,
        @RequestParam("mfa_token") tokenChallenge: String,
        @RequestParam("totpToken") totpToken: String,
    ): String {
        return try {
            val verifyRequest = VerifyLoginRequestDto(tokenChallenge, totpToken)
            val tokens = mfaLoginService.verifyLogin(verifyRequest)
            response.setCookieExt(
                "access_token",
                tokens.accessToken,
                maxAge = tokens.accessTokenExpireIn
            )
            val nextURI = request.session.getAttribute("next")?.toString()
            val queries = request.session.getAttribute("next_query")?.toString()
            val redirectURI = nextURI?.let { uri ->
                // clear the session attributes
                request.session.removeAttribute("next")
                request.session.removeAttribute("next_query")
                queries?.let { query -> "$uri?$query" } ?: uri
            } ?: "/home"

            redirect.addFlashAttribute("error_type", "success")
            redirect.addFlashAttribute("error_message", "Multi factor authentication validated")

            "redirect:$redirectURI"
        } catch (_: MFANotEnabledException) {
            redirect.addFlashAttribute("error_type", "primary")
            redirect.addFlashAttribute("error_message", "Multi factor authentication is not enabled")
            "redirect:/login"
        } catch (_: MFAInvalidLoginChallengeException) {
            redirect.addFlashAttribute("error_type", "danger")
            redirect.addFlashAttribute("error_message", "Re-login is required")
            "redirect:/login"
        } catch (_: TOTPCodeInvalidException) {
            redirect.addFlashAttribute("error_type", "warning")
            redirect.addFlashAttribute("error_message", "Cannot validate given code")
            "redirect:/verify-login?mfa_token=${tokenChallenge}"
        } catch (e: Exception) {
            redirect.addFlashAttribute("error_type", "danger")
            redirect.addAttribute("error_message", e.message)
            "redirect:/login"
        }
    }
}