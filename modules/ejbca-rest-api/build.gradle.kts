plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    implementation(project(path = ":modules:ejbca-rest-common", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-system", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-configdump", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-endentity", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-certificate", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-ssh", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-ca", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-coap", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-cryptotoken", configuration = "archives"))
    implementation(project(path = ":modules:ejbca-rest-camanagement", configuration = "archives"))
    compileOnly(libs.cert.cvc)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.commons.fileupload)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.java.ee.api)
    compileOnly(libs.x509.common.util)
    implementation(libs.commons.lang3.old)
    implementation(libs.reflections)
    implementation(libs.swagger.annotations)
    implementation(libs.swagger.core)
    implementation(libs.swagger.jaxrs)
    implementation(libs.swagger.models)
    testCompileOnly(libs.cryptotokens.api)
    testCompileOnly(libs.cryptotokens.impl)
    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:systemtests").dependencyProject.sourceSets["test"].output)
    testImplementation(project(":modules:systemtests:interface"))
    testImplementation(libs.bundles.jackson)
    testImplementation(libs.bundles.resteasy.jaxrs)
    testImplementation(libs.jakarta.xml.bind.api)
    testImplementation(libs.json.simple)
    testCompileOnly(project(":modules:ejbca-common-web"))
    testCompileOnly(project(":modules:systemtests:common"))
    testRuntimeOnly(project(":modules:ejbca-ws:common"))
    testRuntimeOnly(libs.bundles.hibernate.validator)
    testRuntimeOnly(libs.classmate)
    testRuntimeOnly(libs.jboss.logging)
}

sourceSets {
    val main by getting {
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
    from("resources/WEB-INF") {
        include("ValidationMessages.properties")
    }
    into("build/resources/test/")
}
