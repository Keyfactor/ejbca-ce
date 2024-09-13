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
    compileOnly(project(":modules:ejbca-ws"))
    compileOnly(project(":modules:systemtests:interface"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(project(":modules:ejbca-ejb"))
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.json.simple)
    compileOnly(libs.junit)
    compileOnly(libs.commons.lang)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
}

sourceSets {
    main {
        java {
            srcDir("../src")
            include("org/cesecore/SystemTestsConfiguration.java")
            include("org/cesecore/audit/impl/*EventTypes.java")
            include("org/cesecore/keys/validation/DnsNameValidatorMock.java")
            include("org/cesecore/certificates/ca/TestExtendedCAServiceInfo.java")
            include("org/cesecore/certificates/ca/TestExtendedCAService.java")
            include("org/cesecore/certificates/ca/TestExtendedCAServiceResponse.java")
            include("org/ejbca/core/ejb/ca/caadmin/UnAuthorizedCustomPublisherMock.java")
            include("org/ejbca/core/ejb/ca/caadmin/AuthorizedCustomPublisherMock.java")
            include("org/ejbca/core/ejb/unidfnr/UnidFnrHandlerMock.java")
            include("org/ejbca/core/ejb/unidfnr/UnidFnrHandlerMock.java")
            include("org/ejbca/ui/web/rest/api/resource/RestResourceSystemTestBase.java")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    from("resources/META-INF") {
        into("META-INF")
    }
    archiveBaseName.set("systemtests-common")
}
