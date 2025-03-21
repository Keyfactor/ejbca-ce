plugins {
    java
    application
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

application {
    mainClass.set("org.ejbca.ui.cli.ClientToolBox")
}

dependencies {
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    //compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.cert.cvc)
    //compileOnly(libs.commons.collections4)
    //compileOnly(libs.commons.codec)
    compileOnly(libs.commons.lang)
    //compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.io)
    compileOnly(libs.httpclient)
    compileOnly(libs.httpcore)
    compileOnly(libs.json.simple)
    compileOnly(libs.log4j.api)
    compileOnly(libs.log4j.core)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    implementation(libs.cryptotokens.api)
    implementation(libs.cryptotokens.impl)
    testImplementation(project(":modules:systemtests"))
    testImplementation(project(":modules:systemtests").dependencyProject.sourceSets["test"].output)
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:ejb"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:ejbca-ejb-interface"))
    testImplementation(libs.bundles.test)
    testImplementation(libs.system.rules)
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
    //from(sourceSets["main"].output)
    manifest {
        attributes(
            "Main-Class" to "org.ejbca.ui.cli.ClientToolBox"
        )
    }
}
