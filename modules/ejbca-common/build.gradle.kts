plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(libs.adsddl)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.jakarta.xml.ws.api)
    compileOnly(libs.jakarta.xml.bind.api)
    compileOnly(libs.httpclient)
    compileOnly(libs.httpcore)
    compileOnly(libs.json.simple)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.text)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.jldap)
    compileOnly(libs.x509.common.util)
    testImplementation(project(":modules:ejbca-ejb-interface"))
    testImplementation(project(":modules:ejbca-common-web"))
    testImplementation(libs.bundles.cryptotokens)
    testRuntimeOnly(libs.cert.cvc)
    testRuntimeOnly(libs.bundles.xmlpull)
    testRuntimeOnly(libs.slf4j.api)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

// define interfaces that should be used to generate service manifest files
ext["serviceInterfaces"] = listOf(
    "org.cesecore.authentication.tokens.AuthenticationTokenMetaData",
    "org.cesecore.configuration.ConfigurationCache",
    "org.ejbca.core.model.approval.profile.ApprovalProfile",
    "org.cesecore.keys.validation.Validator",
    "org.ejbca.core.model.validation.domainblacklist.DomainBlacklistNormalizer",
    "org.ejbca.core.model.validation.domainblacklist.DomainBlacklistChecker"
)

tasks.jar {
    from(sourceSets["main"].output)
    // include the static service manifest files for "org.ejbca.core.model.ca.publisher.CTCustomPublisher"
    from(sourceSets["main"].java.srcDirs) {
        include("META-INF/**")
    }
}
