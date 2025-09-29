plugins {
    java
}

dependencies {
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.configuration2)
    implementation(libs.jakartaee.api)
    implementation(libs.log4j.api)
    implementation(libs.log4j.core)
    implementation(libs.log4j.v12.api)
    implementation(libs.x509.common.util)
    compileOnly(libs.xmlpull)
    compileOnly(libs.bundles.cryptotokens)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-entity"))
    testImplementation(libs.junit)
    testImplementation(libs.hamcrest.core)
    testRuntimeOnly(libs.xpp3.min)
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
}
