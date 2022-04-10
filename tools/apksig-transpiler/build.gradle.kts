import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.6.10"
    application
}

group = "signingserver"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "10"
}

application {
    dependencies {
        implementation("com.github.javaparser:javaparser-symbol-solver-core:3.24.2")
    }
    mainClass.set("MainKt")
}