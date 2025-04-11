plugins {
    java
    application
}

application {
    mainClass.set("org.ejbca.ui.cli.ClientToolBox")
}

dependencies {
    implementation(libs.bundles.bouncy.castle)
    implementation(libs.bundles.cryptotokens)
    implementation(libs.bundles.soap.client)
    implementation(libs.bundles.utils)
    implementation(libs.cert.cvc)
    implementation(libs.httpclient)
    implementation(libs.httpcore)
    implementation(libs.httpmime)
    implementation(libs.json.simple)
    implementation(libs.x509.common.util)
    implementation(project(":modules:cesecore-common"))
    implementation(project(":modules:cesecore-ejb-interface"))
    implementation(project(":modules:ejbca-common"))
    implementation(project(":modules:ejbca-common-web"))
    runtimeOnly(libs.angus.activation)
    runtimeOnly(libs.ejbca.ws.client.gen)
    runtimeOnly(libs.jacknji11)
    runtimeOnly(libs.jakarta.jws.api)
    runtimeOnly(libs.jakarta.xml.soap.api)
    runtimeOnly(libs.jaxb.core)
    runtimeOnly(libs.jcip.annotations)
    runtimeOnly(libs.jldap)
    runtimeOnly(libs.jna)
    runtimeOnly(libs.nimbus.jose.jwt)
    runtimeOnly(project(":modules:ejbca-ws-cli"))
    testImplementation(project(":modules:systemtests"))
    testImplementation(project(":modules:systemtests").dependencyProject.sourceSets["test"].output)
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:ejb"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:ejbca-ejb-interface"))
    testImplementation(libs.bundles.test)
    testImplementation(libs.system.rules)
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
}

tasks.jar {
    manifest {
        attributes(
            "Main-Class" to "org.ejbca.ui.cli.ClientToolBox",
            "Class-Path" to configurations.runtimeClasspath.get().joinToString(" ") { "lib/${it.name}" }
        )
    }
    doLast {
        val distDir = File("${project.rootDir}/dist/clientToolBox")
        val libDir = distDir.resolve("lib")
        val propertiesDir = distDir.resolve("properties")

        // Create the necessary directories
        listOf(distDir, libDir, propertiesDir).forEach { it.mkdirs() }

        // Copy runtime dependencies to lib directory
        copy {
            from(configurations.runtimeClasspath)
            into(libDir)
        }

        // Copy property files to the properties directory
        copy {
            from("${project.rootDir}/src/internal.properties")
            from("${project.rootDir}/modules/clientToolBox/resources/properties")
            into(propertiesDir)
        }

        // Copy other required files to the distribution directory
        copy {
            from("${project.rootDir}/modules/clientToolBox/build/libs/")
            from("${project.rootDir}/modules/clientToolBox/resources/ejbcaClientToolBox.bat")
            from("${project.rootDir}/modules/clientToolBox/resources/ejbcaClientToolBox.sh")
            from("${project.rootDir}/modules/clientToolBox/resources/README")
            from("${project.rootDir}/modules/ejbca-ws-cli/resources/ejbcawsracli.properties")
            from("${project.rootDir}/modules/ejbca-ws-cli/resources/java-util-logging.properties")
            into(distDir)
        }
    }
}