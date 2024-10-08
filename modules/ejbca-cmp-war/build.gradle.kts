plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.war {
    archiveBaseName.set("cmp")
    webXml = file("resources/WEB-INF/web.xml")
}
