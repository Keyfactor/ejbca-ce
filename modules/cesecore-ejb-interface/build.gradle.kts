plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.io)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    testRuntimeOnly(libs.bundles.xmlpull)
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
