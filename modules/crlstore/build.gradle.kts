plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.commons.lang)
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
    webXml = file("resources/WEB-INF/web-crlstore-ejbca.xml")
}
