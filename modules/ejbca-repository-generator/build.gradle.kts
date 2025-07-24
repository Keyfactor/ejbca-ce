plugins {
    application
    kotlin("jvm") version "1.9.22"
}

tasks.test {
    useJUnitPlatform()
}

application {
    mainClass.set("org.ejbca.repository.generator.Main")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(libs.freemarker)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.dataformat.xml)
    testImplementation(libs.junit)
    implementation(libs.guava)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
        resources {
            srcDirs("resources")
        }
    }
    test {
        java {
            setSrcDirs(listOf("src-test"))
        }
        resources {
            srcDirs("resources-test")
        }
    }
}

tasks.register<JavaExec>("runAfterCompile") {
    group = "application"
    description = "Run the applicationen after compilation."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set(application.mainClass)

    mustRunAfter("classes")
}

tasks.named("compileJava") {
    //finalizedBy("runAfterCompile")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
    }
    archiveBaseName.set("generator")
    archiveVersion.set("")
}
