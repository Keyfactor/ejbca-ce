plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src-interface"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("edition-specific-interface")
}
