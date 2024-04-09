plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(libs.adsddl)
    compileOnly(libs.java.ee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.jaxws.api)
    compileOnly(libs.jakarta.xml.bind.api)
    compileOnly(libs.httpclient)
    compileOnly(libs.httpcore)
    compileOnly(libs.json.simple)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.lang)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.jldap)
    compileOnly(libs.x509.common.util)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    from("resources/META-INF/services") {
        into("META-INF/services")
    }
}
