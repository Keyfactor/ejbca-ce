plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ws:common"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-repository"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.jaxb.runtime)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    testImplementation(libs.junit)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
    test {
        java {
            setSrcDirs(listOf("src-test"))
        }
        resources {
            srcDirs("resources-test")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("ejbca-interface")
}
