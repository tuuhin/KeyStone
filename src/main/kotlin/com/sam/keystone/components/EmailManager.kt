package com.sam.keystone.components

import com.sam.keystone.entity.User
import com.sendgrid.Method
import com.sendgrid.Request
import com.sendgrid.SendGrid
import com.sendgrid.helpers.mail.Mail
import com.sendgrid.helpers.mail.objects.Content
import com.sendgrid.helpers.mail.objects.Email
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import org.thymeleaf.context.Context
import org.thymeleaf.spring6.SpringTemplateEngine

@Component
class EmailManager(
    private val templateEngine: SpringTemplateEngine,
) {

    @Value($$"${spring.sendgrid.api-key}")
    lateinit var sendGridApiKey: String

    @Value($$"${sendgrid.sender-email}")
    lateinit var senderEmail: String

    @Value($$"${app.backend-uri}")
    lateinit var appURI: String

    private val logger = LoggerFactory.getLogger(this::class.java)

    @Async
    fun sendVerificationEmailHtml(user: User, verificationToken: String) {
        val subject = "Verify Your Email - Keystone"

        val verifyLink = "$appURI/verify?token=${verificationToken}"
        logger.debug(verifyLink)

        // Prepare template context
        val context = Context().apply {
            setVariable("userName", user.userName)
            setVariable("verifyLink", verifyLink)
        }
        val htmlContent = templateEngine.process("verify_email.html", context)

        // prepare the email to send
        val fromEmail = Email(senderEmail)
        val toEmail = Email(user.email)
        val contentType = Content("text/html", htmlContent)
        val composition = Mail(fromEmail, subject, toEmail, contentType)

        // send the mail finally
        try {
            val sendGrid = SendGrid(sendGridApiKey)

            val request = Request().apply {
                method = Method.POST
                endpoint = "mail/send"
                body = composition.build()
            }
            val response = sendGrid.api(request)
            logger.debug("SendGrid Response: ${response.statusCode}")
        } catch (e: Exception) {
            logger.error("Sendgrid response failed :${e.message}", e)
        }
    }

}