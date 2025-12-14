package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.mfa.dto.VerifyLoginRequestDto
import com.sam.keystone.modules.mfa.exceptions.MFAInvalidLoginChallengeException
import com.sam.keystone.modules.mfa.exceptions.MFANotEnabledException
import com.sam.keystone.modules.mfa.exceptions.TOTPCodeInvalidException
import com.sam.keystone.modules.mfa.services.MFAVerifyLoginService
import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.response.LoginResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import com.sam.keystone.modules.user.service.AuthRegisterLoginService
import com.sam.keystone.security.utils.setCookieExt
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import kotlin.time.Duration

@Controller
@RequestMapping("/")
class UserAuthController(
    private val loginService: AuthRegisterLoginService,
    private val mfaLoginService: MFAVerifyLoginService,
) {

    @GetMapping("home")
    fun basicHome(model: Model, @AuthenticationPrincipal user: User): String {
        model.addAttribute("user", user)
        return "home"
    }

    @GetMapping("login")
    fun loginScreen(request: HttpServletRequest, model: Model): String {
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        return "login"
    }

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

    @GetMapping("register")
    fun registerUserScreen(request: HttpServletRequest, model: Model): String {
        val cookie = request.cookies.find { it.name == "mfa_token" }?.value ?: ""
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        model.addAttribute("mfa_token", cookie)
        return "register"
    }


    @GetMapping("logout")
    fun logOutUser(request: HttpServletRequest, response: HttpServletResponse): String {
        // clear the session and clear a blank cookie that expires
        request.session.removeAttribute("next")
        request.session.removeAttribute("next_query")
        response.setCookieExt("access_token", null, maxAge = Duration.ZERO)
        return "redirect:/login"
    }

    @PostMapping("login", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun loginViaCredentials(
        request: HttpServletRequest,
        response: HttpServletResponse,
        redirect: RedirectAttributes,
        @RequestParam("username") uName: String,
        @RequestParam("password") pWord: String,
    ): String {
        return try {
            val loginRequest = LoginUserRequest(uName, pWord)
            when (val result = loginService.loginUser(loginRequest, createRefreshToken = false)) {
                is LoginResponseDto.LoginResponseWith2Fa -> {
                    // keep the session response to redirect the request later if token is correct
                    // redirect to verify token
                    "redirect:verify-login?mfa_token=${result.mfaResponse.token}"
                }

                is LoginResponseDto.LoginResponseWithTokens -> {
                    // set the cookie
                    response.setCookieExt(
                        name = "access_token",
                        value = result.tokens.accessToken,
                        maxAge = result.tokens.accessTokenExpireIn
                    )
                    // if login was a redirect then redirect to the original one requested
                    // the original information about routes and query is kept in session
                    val nextURI = request.session.getAttribute("next")?.toString()
                    val queries = request.session.getAttribute("next_query")?.toString()
                    val redirectURI = nextURI?.let { uri ->
                        // clear the session attributes
                        request.session.removeAttribute("next")
                        request.session.removeAttribute("next_query")
                        queries?.let { query -> "$uri?$query" } ?: uri
                    } ?: "/home"

                    redirect.addFlashAttribute("error_type", "success")
                    redirect.addFlashAttribute("error_message", "User logged in successfully")
                    "redirect:$redirectURI"
                }
            }
        } catch (e: UserAuthException) {
            redirect.addFlashAttribute("error_type", "danger")
            redirect.addFlashAttribute("error_message", e.message)
            "redirect:/login"
        } catch (e: UserVerificationException) {
            redirect.addFlashAttribute("error_type", "info")
            redirect.addFlashAttribute("error_message", e.message)
            "redirect:/login"
        }
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