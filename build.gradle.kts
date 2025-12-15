plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "3.5.7"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("plugin.jpa") version "2.2.21"
}

group = "com.sam"
version = "0.0.1-SNAPSHOT"
description = "Demo project for Spring Boot"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(19)
    }
}

repositories {
    mavenCentral()
}

dependencies {

    // spring
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    implementation("dev.samstevens.totp:totp-spring-boot-starter:1.7.1")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // db
    implementation("org.flywaydb:flyway-core")
    runtimeOnly("org.hibernate.orm:hibernate-community-dialects")
    runtimeOnly("org.xerial:sqlite-jdbc:3.45.3.0")

    // qr code
    implementation("com.google.zxing:core:3.5.4")
    implementation("commons-codec:commons-codec:1.17.0")
    // aws s3 starter
    implementation("io.awspring.cloud:spring-cloud-aws-starter-s3:3.4.2")
    // swagger docs
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.14")
    // jwts
    implementation("org.bouncycastle:bcprov-jdk18on:1.82")
    implementation("com.auth0:java-jwt:4.5.0")
    // redis
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    //emails
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("com.sendgrid:sendgrid-java:4.10.3")
    // templating
    implementation("io.pebbletemplates:pebble-spring-boot-starter:4.0.0")

    // spring test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

allOpen {
    annotation("jakarta.persistence.Entity")
    annotation("jakarta.persistence.MappedSuperclass")
    annotation("jakarta.persistence.Embeddable")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
