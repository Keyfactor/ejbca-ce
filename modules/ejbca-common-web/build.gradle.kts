plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(libs.angus.activation)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.io)
    compileOnly(libs.jldap)
    compileOnly(libs.myfaces.api)
    compileOnly(libs.x509.common.util)
    testImplementation(project(":modules:ejbca-entity"))
    testImplementation(project(":modules:ejbca-ejb"))
    testRuntimeOnly(libs.myfaces.api)
    testRuntimeOnly(libs.jakarta.xml.bind.api)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
        resources {
            srcDirs("resources")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}