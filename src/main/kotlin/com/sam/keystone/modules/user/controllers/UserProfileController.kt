package com.sam.keystone.modules.user.controllers

import com.sam.keystone.modules.user.service.UserUpdateEmailService
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
@RequestMapping("/profile")
class UserProfileController(private val service: UserUpdateEmailService) {

    @GetMapping("/email-change/verify")
    fun verifyEmailAndLogout(@RequestParam("token") token: String, model: Model): String {
        return try {
            service.verifyUpdateEmailRequest(token)
            "email_update/email_update_success_page"
        } catch (e: Exception) {
            model.addAttribute("error_message", e.message)
            "email_update/email_update_failed_page"
        }
    }
}