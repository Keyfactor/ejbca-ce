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
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(project(":modules:ejbca-ws:common"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(libs.ejbca.ws.client.gen)
    compileOnly(libs.caffeine)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.jakarta.xml.ws.api)
    compileOnly(libs.jaxb.runtime)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.guava)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    testRuntimeOnly(libs.jldap)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
            exclude("org/ejbca/util/EjbDependencyGraphTool.java")
        }
    }
}

tasks.jar {
    from("resources") {
        include("ejb-jar.xml")
        include("jboss-ejb3.xml")
        into("META-INF")
    }
    from("resources/META-INF/services") {
        into("META-INF/services")
    }
    from(sourceSets["main"].output)
}
