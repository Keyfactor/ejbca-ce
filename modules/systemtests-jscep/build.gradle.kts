plugins {
    java
}

dependencies {
    implementation(libs.jaxb.core)
    implementation(libs.jldap)
    testImplementation(project(":modules:cesecore-common"))
    testImplementation(project(":modules:cesecore-ejb-interface"))
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:edition-specific:interface"))
    testImplementation(project(":modules:ejbca-ejb-interface"))
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:ejb"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:ejbca-repository"))
    testImplementation(project(":modules:ejbca-common"))
    testImplementation(project(":modules:cesecore-x509ca"))
    testImplementation(libs.bcprov)
    testImplementation(libs.bcpkix)  
    testImplementation(libs.slf4j.api)
    testImplementation(libs.bcutil)
    testImplementation(libs.jcip.annotations)
    testImplementation(libs.jakarta.servlet.api)
    testImplementation(libs.x509.common.util)
    testImplementation(libs.bundles.cryptotokens)
    testImplementation(libs.cert.cvc)
}

sourceSets {
    test {
        java {
            setSrcDirs(listOf("src-test"))
        }
    }
}

tasks.processTestResources {
    from("${rootProject.projectDir}/conf") {
        include("jndi.properties.jboss7")
        rename("jndi.properties.jboss7", "jndi.properties")
    }
    from("${rootProject.projectDir}/src/java")
    {
        include("defaultvalues.properties")
    }
    from("${rootProject.projectDir}/src/appserver/jboss/jboss7")
    {
        include("jboss-ejb-client.properties")
    }
    into("build/resources/test/")
}

tasks.systemTest {
    enabled = true
}