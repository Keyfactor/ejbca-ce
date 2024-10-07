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
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
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
    compileOnly(libs.istack.commons.runtime.old)
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
            resources {
                srcDirs("resources")
            }
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
        include("certextensions.properties")
    }
    into("build/resources/test/")
}

tasks.jar {
    from(sourceSets["main"].output)
    from("${rootProject.projectDir}/src/java") {
        include("defaultvalues.properties")
        include("dncomponents.properties")
        include("profilemappings.properties")
        include("profilemappings_enterprise.properties")
        include("certextensions.properties")
    }
    from("${rootProject.projectDir}/src/intresources") {
        into("intresources")
    }
}
