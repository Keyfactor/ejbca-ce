plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(libs.bundles.cryptotokens)
    testImplementation(libs.bundles.xmlpull)
    testRuntimeOnly(libs.cert.cvc)
}

sourceSets {
    main {
        java {
            setSrcDirs(
                listOf("src")
            )
            resources {
                srcDirs("resources")
            }
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}
