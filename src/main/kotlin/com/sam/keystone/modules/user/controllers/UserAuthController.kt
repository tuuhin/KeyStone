package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.request.RegisterUserRequest
import com.sam.keystone.modules.user.dto.response.LoginResponseDto
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import com.sam.keystone.modules.user.service.AuthRegisterLoginService
import com.sam.keystone.security.utils.setCookieExt
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
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
) {

    @GetMapping("login")
    fun loginScreen(request: HttpServletRequest, model: Model): String {
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        return "login"
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


    @GetMapping("register")
    fun registerUserScreen(request: HttpServletRequest, model: Model): String {
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        return "register"
    }


    @PostMapping("register")
    fun registerUser(
        redirect: RedirectAttributes,
        @RequestParam("username") uName: String,
        @RequestParam("password") pWord: String,
        @RequestParam("email") email: String,
    ): String {
        val registerRequest = RegisterUserRequest(email = email, userName = uName, password = pWord)
        try {
            loginService.createNewUser(registerRequest)
            redirect.addFlashAttribute("error_type", "success")
            redirect.addFlashAttribute("error_message", "User successfully register,Check your email for verification")
        } catch (e: UserValidationException) {
            redirect.addFlashAttribute("error_type", "warning")
            redirect.addFlashAttribute("error_message", e.message)
        }
        return "redirect:/login"
    }


    @GetMapping("logout")
    fun logOutUser(request: HttpServletRequest, response: HttpServletResponse): String {
        // clear the session and clear a blank cookie that expires
        request.session.removeAttribute("next")
        request.session.removeAttribute("next_query")
        response.setCookieExt("access_token", null, maxAge = Duration.ZERO)
        return "redirect:/login"
    }
}