package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.user.service.AuthVerificationService
import com.sam.keystone.modules.user.service.UserPasswordManagementService
import com.sam.keystone.modules.user.service.UserUpdateEmailService
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.servlet.mvc.support.RedirectAttributes

@Controller
@RequestMapping("/")
class EmailResponseController(
    private val updateEmailService: UserUpdateEmailService,
    private val authVerifyService: AuthVerificationService,
    private val pWordService: UserPasswordManagementService,
) {

    @GetMapping("profile/email-change/verify")
    fun verifyEmailAndLogout(@RequestParam("token") token: String, model: Model): String {
        try {
            updateEmailService.verifyUpdateEmailRequest(token)
            model.addAttribute("is_success", true)
            model.addAttribute("error_type", "success")
        } catch (e: Exception) {
            model.addAttribute("is_success", false)
            model.addAttribute("error_message", e.message)
            model.addAttribute("error_type", "danger")
        }
        return "email_result/email_update_page"
    }

    @GetMapping("auth/verify")
    fun verifyUser(@RequestParam token: String, model: Model): String {
        try {
            authVerifyService.verifyRegisterToken(token)
            model.addAttribute("is_success", true)
            model.addAttribute("error_message", "Hello user your email is verified")
            model.addAttribute("error_type", "success")
        } catch (e: Exception) {
            model.addAttribute("is_success", false)
            model.addAttribute("error_message", e.message)
            model.addAttribute("error_type", "danger")
        }

        return "email_result/user_email_verify_page"
    }

    @GetMapping("auth/password/reset/confirm")
    fun confirmPasswordPage(
        model: Model,
        request: HttpServletRequest,
        @RequestParam("token") token: String = "",
    ): String {
        model.addAttribute("reset_token", token)
        val csrfToken = request.getAttribute("_csrf") as CsrfToken
        model.addAttribute("_csrf", csrfToken)
        return "email_result/password_reset_form"
    }

    @PostMapping("auth/password/reset/confirm")
    fun confirmPasswordResetWeb(
        @RequestParam("token") token: String,
        @RequestParam("new_password") password: String,
        redirect: RedirectAttributes,
    ): String {
        try {
            pWordService.confirmPasswordChange(token, password)
            redirect.addFlashAttribute("error_message", "Password reset complete")
            redirect.addFlashAttribute("error_type", "success")
        } catch (e: Exception) {
            redirect.addFlashAttribute("error_message", e.message)
            redirect.addFlashAttribute("error_type", "danger")
        }
        return "redirect:/login"
    }
}