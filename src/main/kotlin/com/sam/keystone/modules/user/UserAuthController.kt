package com.sam.keystone.modules.user

import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.service.AuthRegisterLoginService
import jakarta.servlet.http.Cookie
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
import kotlin.time.Duration.Companion.minutes

@Controller
@RequestMapping("/")
class UserAuthController(
    private val loginService: AuthRegisterLoginService,
) {

    @GetMapping("home")
    fun basicHome(model: Model, @AuthenticationPrincipal user: User): String {
        model.addAttribute("user", user)
        return "home"
    }

    @GetMapping("login")
    fun loginScreen(
        request: HttpServletRequest,
        model: Model,
        @RequestParam(required = false) error: String?,
    ): String {
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        if (error != null) {
            model.addAttribute("error", "Invalid username or password")
        }
        return "login"
    }

    @GetMapping("logout")
    fun logOutUser(request: HttpServletRequest, response: HttpServletResponse): String {
        val cancelCookie = Cookie("access_token", null).apply {
            path = "/"
            maxAge = 0
            isHttpOnly = true
            secure = true
        }
        // clear the session and clear a blank cookie that expires
        request.session.removeAttribute("next")
        request.session.removeAttribute("next_query")
        response.addCookie(cancelCookie)
        return "redirect:/login"
    }

    @PostMapping("login", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun loginViaCredentials(
        @RequestParam username: String,
        @RequestParam password: String,
        request: HttpServletRequest,
        response: HttpServletResponse,
    ): String {
        // handle the redirect info
        val nextURI = request.session.getAttribute("next")?.toString()
        val queries = request.session.getAttribute("next_query")?.toString()
        val redirectURI = nextURI?.let { uri ->
            // clear the session attributes
            request.session.removeAttribute("next")
            request.session.removeAttribute("next_query")
            // build the uri now
            queries?.let { query -> "$uri?$query" } ?: uri
        } ?: "/home"

        return try {
            val ttl = 30.minutes
            val results = loginService.loginUser(
                request = LoginUserRequest(username, password),
                accessTokenTTL = ttl,
                createRefreshToken = false
            )
            val cookie = Cookie("access_token", results.accessToken).apply {
                isHttpOnly = true
                path = "/"
                secure = true
                maxAge = ttl.inWholeSeconds.toInt()
            }
            response.addCookie(cookie)
            "redirect:$redirectURI"
        } catch (_: Exception) {
            "redirect:/login?error=true"
        }
    }
}