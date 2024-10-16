plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.jaxb.runtime)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.x509.common.util)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src/org/ejbca/core/protocol/ws/common", "../src/org/ejbca/core/protocol/ws/objects"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("ejbca-ws")
}
