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
    compileOnly(libs.cryptotokens.impl)
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(libs.cryptotokens.api)
    testImplementation(libs.cert.cvc)
    testImplementation(libs.bundles.xmlpull)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(
                listOf("src")
            )
            resources.srcDirs("resources")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}
