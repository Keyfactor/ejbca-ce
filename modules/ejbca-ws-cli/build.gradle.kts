plugins {
    java
}

dependencies {
    implementation(project(":modules:cesecore-common"))
    implementation(project(":modules:ejbca-common"))
    implementation(project(":modules:ejbca-ws:common"))
    implementation(libs.jakarta.xml.ws.api)
    implementation(libs.bcpkix)
    implementation(libs.bcprov)
    implementation(libs.bctls)
    implementation(libs.bcutil)
    implementation(libs.cert.cvc)
    implementation(libs.ejbca.ws.client.gen)
    implementation(libs.commons.lang)
    implementation(libs.x509.common.util)
    implementation(libs.bundles.cryptotokens)
    implementation(libs.istack.commons.runtime)
    implementation(libs.jakarta.xml.bind.api)
    implementation(libs.saaj.impl)
    implementation(libs.streambuffer)
    implementation(libs.woodstox.core)
    implementation(libs.wsdl4j)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("ejbca-ws-client")
}

tasks.processTestResources {
    from("resources"){
        include("ejbcawsracli.properties")
    }
    into("build/resources/test/")
}
