plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(libs.jakarta.xml.ws.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    compileOnly(libs.jakarta.persistence.api)
    testImplementation(project(":modules:cesecore-common").dependencyProject.sourceSets["test"].output)
    testRuntimeOnly(libs.cert.cvc)
}

sourceSets {
    main {
        java {
            setSrcDirs(
                listOf("src")
            )
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}
