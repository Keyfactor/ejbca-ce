import org.apache.tools.ant.filters.EscapeUnicode

plugins {
    java
    war
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:ejbca-common-web"))
    compileOnly(project(":modules:ejbca-ejb-interface"))
    compileOnly(project(":modules:ejbca-entity"))
    compileOnly(project(":modules:edition-specific:interface"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.commons.codec)
    compileOnly(libs.commons.collections4)
    compileOnly(libs.commons.io)
    compileOnly(libs.commons.lang)
    compileOnly(libs.guava)
    compileOnly(libs.cert.cvc)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.snakeyaml)
    compileOnly(libs.nimbus.jose.jwt)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.bundles.cryptotokens)
    compileOnly(libs.jldap)
    if (project.extra["edition"] == "ee") {
        compileOnly(project(":modules:peerconnector:common"))
        compileOnly(project(":modules:peerconnector:interface"))
        compileOnly(project(":modules:peerconnector:publ"))
        compileOnly(project(":modules:peerconnector:ra"))
        compileOnly(project(":modules:acme:common"))
    }
    implementation(libs.csrfguard)
    implementation(libs.csrfguard.extension.session)
    implementation(libs.csrfguard.jsp.tags)
    implementation(libs.primefaces)
    testRuntimeOnly(libs.myfaces.api)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
            if (project.extra["edition"] == "ce") {
                exclude("org/ejbca/ui/web/admin/acme/AcmeConfigMBean.java")
                exclude("org/ejbca/ui/web/admin/acme/AcmeAliasConfigMBean.java")
                exclude("org/ejbca/ui/web/admin/peerconnector")
            }
        }
    }
}

tasks.war {
    archiveBaseName.set("adminweb")
    from("resources") {
        exclude("languages/*")
    }
    from("resources") {
        include("languages/*")
        exclude("languages/language-tool.sh")
        exclude("languages/check-trad.pl")
        if (project.extra["edition"] == "ce") {
            exclude("peerconnector")
        }
        filter(EscapeUnicode::class)
    }
}
