// This module is only required for CLI tools.  Which at the time this was
// checked in didn't have gradle support.  When that is added, we need to 
// change the dependencies below to include jboss-client.jar.
plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(libs.log4j.v12.api)
}

sourceSets {
    main {
        java {
            setSrcDirs(
                listOf("src")
            )
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}
