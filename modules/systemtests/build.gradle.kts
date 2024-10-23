plugins {
    java
}

dependencies {
    implementation(libs.cert.cvc)
    implementation(libs.jldap)
    testImplementation(project(":modules:cesecore-common"))
    testImplementation(project(":modules:cesecore-ejb-interface"))
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:cesecore-x509ca"))
    testImplementation(project(":modules:edition-specific:interface"))
    testImplementation(project(":modules:ejbca-common"))
    testImplementation(project(":modules:ejbca-common").dependencyProject.sourceSets["test"].output)
    testImplementation(project(":modules:ejbca-common-web"))
    testImplementation(project(":modules:ejbca-ejb"))
    testImplementation(project(":modules:ejbca-ejb-cli"))
    testImplementation(project(":modules:ejbca-ejb-interface"))
    testImplementation(project(":modules:ejbca-entity"))
    testImplementation(project(":modules:ejbca-rest-common"))
    testImplementation(project(":modules:ejbca-ws"))
    testImplementation(project(":modules:ejbca-ws:common"))
    testImplementation(project(":modules:peerconnector:common"))
    testImplementation(project(":modules:peerconnector:interface"))
    testImplementation(project(":modules:plugins"))
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:ejb"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:va:extensions"))
    testImplementation(libs.angus.activation)
    testImplementation(libs.bundles.bouncy.castle)
    testImplementation(libs.bundles.resteasy.jaxrs)
    testImplementation(libs.bundles.xstream)
    testImplementation(libs.cert.cvc)
    testImplementation(libs.bundles.cryptotokens)
    testImplementation(libs.ejbca.ws.client.gen)
    testImplementation(libs.hibernate.core)
    testImplementation(libs.jakarta.xml.bind.api)
    testImplementation(libs.jakartaee.api)
    testImplementation(libs.jakarta.xml.ws.api)
    testImplementation(libs.json.simple)
    testImplementation(libs.keyfactor.commons.cli)
    testImplementation(libs.nimbus.jose.jwt)
    testImplementation(libs.x509.common.util)

    if (project.extra["edition"] == "ee") {
        testImplementation(project(":modules:acme:common"))
        testImplementation(project(":modules:ct"))
        testImplementation(project(":modules:ejbca-entity:cli"))
        testImplementation(project(":modules:peerconnector:publ"))
    }
    implementation("org.jboss:jboss-remote-naming:2.0.5.Final")
    implementation("org.jboss.logging:jboss-logging:3.6.1.Final")
    implementation("org.jboss.remoting:jboss-remoting:5.0.29.Final")

    implementation("org.glassfish.hk2:osgi-resource-locator:2.5.0-b42")
    implementation("com.sun.xml.ws:jaxws-rt:4.0.1")
    implementation(libs.jaxb.core)
    testRuntimeOnly(libs.jaxb.impl)
    implementation("com.sun.xml.stream.buffer:streambuffer:2.1.0")
    implementation("org.jvnet.staxex:stax-ex:1.8")
    implementation("org.glassfish.gmbal:gmbal:4.0.3")

    // System test specific
    testRuntimeOnly(libs.bundles.resteasy.jaxrs) // TODO: ECA-12372 - check if the dependency is really needed
    testRuntimeOnly(libs.jakarta.mail)
}

sourceSets {
    test {
        resources {
            srcDirs("resources")
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