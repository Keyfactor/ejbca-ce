plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(libs.java.ee.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.log4j.v12.api)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.war {
    archiveBaseName.set("clearcache")
    webXml = file("resources/WEB-INF/web.xml")
}
