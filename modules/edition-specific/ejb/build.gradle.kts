plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.cryptotokens.api)
    compileOnly(libs.cryptotokens.impl)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(listOf("../src-ejb"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("edition-specific-ejb")
}

