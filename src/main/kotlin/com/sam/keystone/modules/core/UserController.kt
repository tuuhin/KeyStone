package com.sam.keystone.modules.core

import com.sam.keystone.modules.user.entity.User
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class UserController {

    @GetMapping("home")
    fun basicHome(model: Model, @AuthenticationPrincipal user: User): String {
        model.addAttribute("user", user)
        return "home"
    }
}