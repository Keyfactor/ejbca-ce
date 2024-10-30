plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.x509.common.util)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src-war"))
        }
    }
}

tasks.war {
    from("resources/WEB-INF") {
        include("web-status-ejbca.xml")
        rename("web-status-ejbca.xml", "web.xml")
        into("WEB-INF")
    }
    from("resources/WEB-INF/META-INF") {
        into("WEB-INF/classes/META-INF")
    }
    archiveBaseName.set("status")
}
