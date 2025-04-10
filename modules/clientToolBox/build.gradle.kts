plugins {
    java
    application
}

application {
    mainClass.set("org.ejbca.ui.cli.ClientToolBox")
}

dependencies {
    implementation(libs.bcpkix)
    implementation(libs.bcprov)
    implementation(libs.bctls)
    implementation(libs.bcutil)
    implementation(libs.cert.cvc)
    implementation(libs.commons.beanutils)
    implementation(libs.commons.collections4)
    implementation(libs.commons.codec)
    implementation(libs.commons.lang)
    implementation(libs.commons.lang3)
    implementation(libs.commons.io)
    implementation(libs.commons.logging)
    implementation(libs.commons.text)
    implementation(libs.httpclient)
    implementation(libs.httpcore)
    implementation(libs.json.simple)
    implementation(libs.log4j.api)
    implementation(libs.log4j.core)
    implementation(libs.log4j.v12.api)
    implementation(libs.x509.common.util)
    implementation(project(":modules:cesecore-common"))
    implementation(project(":modules:cesecore-ejb-interface"))
    implementation(project(":modules:ejbca-common"))
    implementation(project(":modules:ejbca-common-web"))
    implementation(libs.cryptotokens.api)
    implementation(libs.cryptotokens.impl)
    implementation(libs.commons.configuration2)
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
        val libDir = File("${project.rootDir}/dist/clientToolBox/lib/")
        libDir.mkdirs()
        configurations.runtimeClasspath.get().forEach { file ->
            copy {
                from(file)
                into(libDir)
            }
        }
        val targetDir = File("${project.rootDir}/dist/clientToolBox/")
        targetDir.mkdirs()
        copy {
            from(File("${project.rootDir}/modules/clientToolBox/build/libs/"))
            from(File("${project.rootDir}/modules/clientToolBox/resources/ejbcaClientToolBox.bat"))
            from(File("${project.rootDir}/modules/clientToolBox/resources/ejbcaClientToolBox.sh"))
            from(File("${project.rootDir}/modules/clientToolBox/resources/README"))
            from(File("${project.rootDir}/modules/ejbca-ws-cli/resources/ejbcawsracli.properties"))
            into(targetDir)
        }
        val propertiesDir = File("${project.rootDir}/dist/clientToolBox/properties/")
        targetDir.mkdirs()
        copy {
            from(File("${project.rootDir}/src/internal.properties"))
            from(File("${project.rootDir}/modules/clientToolBox/resources/properties"))
            into(propertiesDir)
        }
    }
}
