/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0
 */

plugins {
    java
}

group = "com.rfc5789"
version = "1.0.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.4")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2025.4")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<Jar>("fatJar") {
    archiveBaseName.set("rfc5789-auditor")
    archiveVersion.set(project.version.toString())
    archiveClassifier.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    })

    manifest {
        attributes(
            "Implementation-Title" to "RFC 5789 Auditor",
            "Implementation-Version" to project.version
        )
    }
}

tasks.named("build") {
    dependsOn("fatJar")
}
