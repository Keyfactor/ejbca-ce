plugins {
    java
}

dependencies {
    implementation(libs.cert.cvc)
    implementation(libs.jaxb.core)
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
    testImplementation(project(":modules:plugins"))
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:ejb"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(project(":modules:va:extensions"))

    if (project.extra["edition"] == "ee") {
        testImplementation(project(":modules:acme:common"))
        testImplementation(project(":modules:ct"))
        testImplementation(project(":modules:ejbca-entity:cli"))
        testImplementation(project(":modules:peerconnector:publ"))
        testImplementation(project(":modules:cesecore-cvcca"))
        testImplementation(project(":modules:peerconnector:common"))
        testImplementation(project(":modules:peerconnector:interface"))
        testImplementation(libs.p11ng)
    }

    testImplementation(libs.angus.activation)
    testImplementation(libs.bundles.bouncy.castle)
    testImplementation(libs.bundles.cryptotokens)
    testImplementation(libs.bundles.resteasy.jaxrs)
    testImplementation(libs.bundles.xstream)
    testImplementation(libs.caffeine)
    testImplementation(libs.cert.cvc)
    testImplementation(libs.ejbca.ws.client.gen)
    testImplementation(libs.hibernate.core)
    testImplementation(libs.jakarta.xml.bind.api)
    testImplementation(libs.jakarta.xml.ws.api)
    testImplementation(libs.jakartaee.api)
    testImplementation(libs.json.simple)
    testImplementation(libs.keyfactor.commons.cli)
    testImplementation(libs.nimbus.jose.jwt)
    testImplementation(libs.x509.common.util)

    if (project.extra["edition"] == "ee") {
        testRuntimeOnly(project(":modules:peerconnector:common"))
        testRuntimeOnly(libs.ctlog)
    }

    testRuntimeOnly(libs.bundles.resteasy.jaxrs)
    testRuntimeOnly(libs.gmbal.api)
    testRuntimeOnly(libs.jakarta.mail)
    testRuntimeOnly(libs.jaxb.impl)
    testRuntimeOnly(libs.jaxws.rt)
    testRuntimeOnly(libs.stax.ex)
    testRuntimeOnly(libs.streambuffer)
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