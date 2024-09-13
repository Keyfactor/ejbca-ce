plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(project(":modules:ejbca-ws:common"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.commons.lang)
    compileOnly(libs.jakarta.jws.api)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
            exclude("org/ejbca/core/protocol/ws/common")
            exclude("org/ejbca/core/protocol/ws/objects")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("ejbca-ws-ejb")
    from("resources/META-INF") {
        into("META-INF")
    }
}
