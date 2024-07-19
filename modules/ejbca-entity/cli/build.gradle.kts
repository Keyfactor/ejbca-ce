plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(libs.java.ee.api)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.xstream)
    compileOnly(libs.hibernate.core)
    compileOnly(libs.bundles.bouncy.castle)
    compileOnly(libs.commons.configuration2)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src-cli"))
        }
    }
}
