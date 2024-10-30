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
    compileOnly(project(":modules:ejbca-ws:common"))
    compileOnly(project(":modules:ejbca-ejb"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(project(":modules:systemtests:interface"))
    compileOnly(project(":modules:systemtests:common"))
    implementation(libs.bcpkix)
    implementation(libs.bcprov)
    implementation(libs.bctls)
    implementation(libs.bcutil)
    implementation(libs.jakartaee.api)
    implementation(libs.json.simple)
    implementation(libs.junit)
    compileOnly(libs.commons.lang)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
}

sourceSets {
    main {
        java {
            srcDir("../src")
            exclude("org/cesecore/SystemTestsConfiguration.java")
            exclude("org/cesecore/audit/impl/*EventTypes.java")
            exclude("org/cesecore/certificates/ca/TestExtendedCAServiceInfo.java")
            exclude("org/ejbca/core/ejb/ca/caadmin/UnAuthorizedCustomPublisherMock.java")
            exclude("org/ejbca/core/ejb/ca/caadmin/AuthorizedCustomPublisherMock.java")
            exclude("org/ejbca/core/ejb/unidfnr/UnidFnrHandlerMock.java")
            exclude("org/ejbca/ui/web/rest/api/resource/RestResourceSystemTestBase.java")
			exclude("com/widget/WidgetCustomExtension.java")
        }
        resources {
            srcDirs("resources")
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    archiveBaseName.set("systemtests-ejb")
}
