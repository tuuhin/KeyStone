# 🔐 Keystone Authentication Service

Keystone is a focused Spring Boot application designed to demonstrate and implement multiple modern user authentication
flows.
This service is built using Spring Boot and Spring MVC, providing a secure foundation for user management and
authentication.

## Key Features

- Standard Login: Traditional username and password authentication with `jwts`.
- OAuth 2.0 client provider: Provides additional oauth2 clients interface allowing user to create oauth2 clients
- Two-Factor Authentication (2FA): Enhanced security using time-based one-time passwords (TOTP).

## ⚙️ Technologies

- Framework: Spring Boot (v3.x)
- Web Layer: Spring MVC
- Security: Spring Security
- Database: Sqlite3
- Build Tool: Gradle

## 💻 Getting Started

To get started or to preview the app follow the given instructions

- Clone this repository
  ```bash
    https://github.com/tuuhin/KeyStone
    cd KeyStone
  ```
- Set up the properties : So this project uses `sendgrid` and `redis` as external providers, and we need few keys for
  encryption (can be generated via `openssl` command ). We need to set up a build configuration for `bootRun` with the
  following env
  variables.
  ```properties
  # key paths
  JWT_PUBLIC_KEY_PATH=
  JWT_PRIVATE_KEY_PATH=
  # send grid email provider
  SENDGRID_API_KEY=
  SENDGRID_SENDER_EMAIL=
  #redis connection url
  REDIS_CONNECTION_URL=
  # aes encryption secret
  AES_SECRET=
  ```
- If everything is set run `bootRun`, the server will start with the port configured in `application.properties`

## 🧪 API Documents

All exposed RESTful API routes are documented using Swagger/OpenAPI.

- To find the exact Swagger path, check the springdoc.swagger-ui.path property in your `application.properties` file.
- The typical route is: `http://localhost:<PORT>/swagger-ui.html`

## Conclusion

This project serves as a learning-focused implementation of modern authentication standards. While it is
fully structured, some advanced error handling or edge-case features may be omitted for clarity.