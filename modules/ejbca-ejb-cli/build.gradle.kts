plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(libs.bundles.bouncy.castle)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.commons.beanutils)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.io)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.bundles.cryptotokens)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.keyfactor.commons.cli)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.x509.common.util)

    if (project.extra["edition"] == "ee") {
        compileOnly(libs.p11ng)
    }
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}
