plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.json.simple)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.lang)
    compileOnly(libs.jsch)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    testImplementation(project(":modules:systemtests:ejb"))
    testCompileOnly(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:systemtests").dependencyProject.sourceSets["test"].output)
    compileOnly(project(":modules:ejbca-ejb-interface"))
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:cesecore-x509ca"))
    testRuntimeOnly(libs.cert.cvc)
    testImplementation(libs.cryptotokens.api)
    testImplementation(libs.cryptotokens.impl)
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
