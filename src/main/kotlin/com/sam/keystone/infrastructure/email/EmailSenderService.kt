package com.sam.keystone.infrastructure.email

import com.sam.keystone.config.AppPropertiesConfig
import com.sam.keystone.modules.user.entity.User
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import org.thymeleaf.context.Context
import org.thymeleaf.spring6.SpringTemplateEngine
import java.util.concurrent.CompletableFuture

@Component
class EmailSenderService(
    private val emailSender: EmailSender,
    private val template: SpringTemplateEngine,
    private val appConfig: AppPropertiesConfig,
) {

    @Async
    fun sendUserVerificationEmail(
        user: User,
        verificationToken: String,
    ): CompletableFuture<Boolean> {
        val subject = "Verify Your Email - Keystone"
        val verifyLink = "${appConfig.emailVerifyRedirect}?token=${verificationToken}"

        // Prepare template context
        val context = Context().apply {
            setVariable("userName", user.userName)
            setVariable("verifyLink", verifyLink)
        }
        val htmlContent = template.process("verify_email.html", context)
        return emailSender.sendEmail(title = subject, content = htmlContent, recipient = user.email)
    }
}