plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.xstream)
    compileOnly(libs.bundles.bouncy.castle)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.hibernate.core)
    implementation(libs.hibernate.community.dialects)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src-cli"))
        }
    }
}
