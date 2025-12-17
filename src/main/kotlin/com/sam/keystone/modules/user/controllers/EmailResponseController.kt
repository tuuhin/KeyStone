package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.user.service.AuthVerificationService
import com.sam.keystone.modules.user.service.UserUpdateEmailService
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
@RequestMapping("/")
class EmailResponseController(
    private val updateEmailService: UserUpdateEmailService,
    private val authVerifyService: AuthVerificationService,
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
}