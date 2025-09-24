plugins {
    java
}

dependencies {
    compileOnly(libs.adsddl)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.jakarta.jws.api)
    compileOnly(libs.jakarta.xml.soap.api)
    compileOnly(libs.jakarta.xml.ws.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.log4j.api)
    compileOnly(libs.log4j.core)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.text)
    compileOnly(libs.commons.logging)
    compileOnly(libs.commons.codec)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.io)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.guava)
    compileOnly(libs.httpclient)
    compileOnly(libs.httpcore)
    compileOnly(libs.httpmime)
    compileOnly(libs.jldap)
    compileOnly(libs.json.simple)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.xmlpull)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    // hibernate
    compileOnly(libs.antlr4.runtime)
    compileOnly(libs.byte.buddy)
    compileOnly(libs.classmate)
    compileOnly(libs.fastInfoset)
    compileOnly(libs.hibernate.commons.annotations)
    compileOnly(libs.hibernate.core)
    compileOnly(libs.hibernate.validator)
    compileOnly(libs.istack.commons.runtime.hibernate)
    compileOnly(libs.jakarta.activation.api)
    compileOnly(libs.jandex)
    compileOnly(libs.jakarta.persistence.api)
    compileOnly(libs.jakarta.xml.bind.api)
    compileOnly(libs.jaxb.runtime)
    compileOnly(libs.jboss.transaction.api.v12.spec)
    compileOnly(libs.stax.ex)
    compileOnly(libs.txw2)

    testImplementation(project(":modules:cesecore-entity"))
    testImplementation(project(":modules:cesecore-x509ca"))
    testRuntimeOnly(libs.xpp3.min)

    if (project.extra["edition"] == "ee") {
        testRuntimeOnly(project(":modules:cesecore-cvcca"))
    }
}

sourceSets {
    main {
        java {
            setSrcDirs(
                listOf("src")
            )
        }
    }
    test {
        resources {
            srcDirs("resources-test")
        }
    }
}

tasks.processTestResources {
    from("${rootProject.projectDir}/src/intresources") {
        into("intresources")
    }
    from("${rootProject.projectDir}/src/java")
    {
        include("defaultvalues.properties")
        include("dncomponents.properties")
        include("profilemappings.properties")
        include("profilemappings_enterprise.properties")
    }
    from("${rootProject.projectDir}/conf") {
        // Required by Pkcs11WrapperUnitTest
        include("systemtests.properties")
    }
    into("build/resources/test/")
}

// Required by Pkcs11WrapperUnitTest
tasks.withType<Test> {
    jvmArgs(
        "--add-exports", "jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
    )
}

// define interfaces that should be used to generate service manifest files
ext["serviceInterfaces"] = listOf(
    "org.cesecore.certificates.ocsp.extension.OCSPExtension",
    "org.cesecore.authentication.tokens.AuthenticationTokenMetaData",
    "org.cesecore.certificates.ca.CvcPlugin",
    "org.cesecore.authorization.rules.AccessRulePlugin",
    "org.cesecore.configuration.ConfigurationCache",
    "org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension",
    "org.cesecore.keys.validation.Validator",
    "org.cesecore.certificates.ca.CACommon",
    "com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapperFactory",
    "com.keyfactor.util.certificate.CertificateImplementation",
    "com.keyfactor.util.crypto.provider.CryptoProvider"
)

tasks.jar {
    from(sourceSets["main"].output)
    from("${rootProject.projectDir}/src/java") {
        include("defaultvalues.properties")
        include("dncomponents.properties")
        include("profilemappings.properties")
        include("profilemappings_enterprise.properties")
    }
    from("${rootProject.projectDir}/src/intresources") {
        into("intresources")
    }
}
