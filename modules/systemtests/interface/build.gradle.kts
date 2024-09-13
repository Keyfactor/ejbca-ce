plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:ejbca-ws:common"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src-interface"))
        }
        resources {
            srcDirs("resources")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    from("${rootProject.projectDir}/conf"){
        include("systemtests.properties")
    }
    archiveBaseName.set("systemtests-interfaces")
}
