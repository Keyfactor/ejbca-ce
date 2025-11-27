plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(libs.cert.cvc)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.commons.fileupload2)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.jackson)
    implementation(project(path = ":modules:ejbca-rest-common", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-ca", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-certificate", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-system", configuration = "archives"))
    if (project.extra["edition"] == "ee") {
        implementation(project(path = ":modules:ejbca-rest-configdump", configuration = "archives"))
        implementation(project(path = ":modules:ejbca-rest-endentity", configuration = "archives"))
        implementation(project(path = ":modules:ejbca-rest-ssh", configuration = "archives"))
        implementation(project(path = ":modules:ejbca-rest-coap", configuration = "archives"))
        implementation(project(path = ":modules:ejbca-rest-cryptotoken", configuration = "archives"))
        implementation(project(path = ":modules:ejbca-rest-camanagement", configuration = "archives"))
    }
    compileOnly(libs.commons.lang3)
    implementation(libs.reflections)
    implementation(libs.swagger.annotations)
    implementation(libs.swagger.core)
    implementation(libs.swagger.jaxrs)
    implementation(libs.swagger.models)
    runtimeOnly(libs.swagger.integration)
    runtimeOnly(libs.classgraph)
    runtimeOnly(libs.javassist)
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:ejbca-common-web"))
    testImplementation(project(":modules:systemtests").dependencyProject.sourceSets["test"].output)
    testImplementation(project(":modules:systemtests:common"))
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(libs.bundles.cryptotokens)
    testImplementation(libs.cryptotokens.api)
    testImplementation(libs.bundles.resteasy.jaxrs)
    testImplementation(libs.bundles.hibernate.validator)
    testImplementation(libs.jakarta.xml.bind.api)
    testImplementation(libs.json.simple)
    testImplementation(libs.hibernate.commons.annotations)
    testImplementation(libs.hibernate.core)
    testImplementation(libs.hibernate.validator)
    testRuntimeOnly(project(":modules:systemtests:ejb"))
    testRuntimeOnly(project(":modules:cesecore-common"))
    testRuntimeOnly(project(":modules:cesecore-x509ca"))
    if (project.extra["edition"] == "ee") {
        testRuntimeOnly(project(":modules:cesecore-cvcca"))
    }
    testRuntimeOnly(project(":modules:ejbca-ws:common"))
    testRuntimeOnly(project(":modules:ejbca-ejb"))
    testRuntimeOnly(project(":modules:ejbca-entity"))
    testRuntimeOnly(libs.jldap)
    testRuntimeOnly(libs.classmate)
    testRuntimeOnly(libs.commons.lang3)
    testRuntimeOnly(libs.resteasy.client)
    testRuntimeOnly(libs.resteasy.client.api)
    testRuntimeOnly(libs.resteasy.core)
    testRuntimeOnly(libs.resteasy.core.spi)
    testRuntimeOnly(libs.resteasy.jackson2.provider)
    testRuntimeOnly(libs.resteasy.multipart.provider)
    testRuntimeOnly(libs.resteasy.undertow)
    testRuntimeOnly(libs.undertow.core)
    testRuntimeOnly(libs.undertow.servlet)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.war {
    webXml = file("resources/WEB-INF/web.xml")
    from("resources/META-INF") {
        into("META-INF")
    }
    from("resources/WEB-INF/ValidationMessages.properties") {
        into("WEB-INF/classes")
    }
}

tasks.processTestResources {
    from("${rootProject.projectDir}/src") {
        include("internal.properties")
    }
    from("resources/WEB-INF") {
        include("ValidationMessages.properties")
    }
    into("build/resources/test/")
}
