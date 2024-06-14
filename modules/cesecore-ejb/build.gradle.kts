plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-ejb-interface"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(project(":modules:cesecore-x509ca"))
    compileOnly(libs.adsddl)
    compileOnly(libs.java.ee.api)
    compileOnly(libs.javax.jws.api)
    compileOnly(libs.javax.xml.soap.api)
    compileOnly(libs.jaxws.api)
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
    compileOnly(libs.cryptotokens.api)
    compileOnly(libs.cryptotokens.impl)
    // hibernate
    compileOnly(libs.antlr)
    compileOnly(libs.byte.buddy)
    compileOnly(libs.classmate)
    compileOnly(libs.dom4j)
    compileOnly(libs.fastInfoset)
    compileOnly(libs.hibernate.commons.annotations)
    compileOnly(libs.hibernate.core)
    compileOnly(libs.hibernate.validator)
    compileOnly(libs.istack.commons.runtime.old)
    compileOnly(libs.jakarta.activation.api)
    compileOnly(libs.jandex)
    compileOnly(libs.javax.persistence.api)
    compileOnly(libs.jaxb.api)
    compileOnly(libs.jaxb.runtime)
    compileOnly(libs.jboss.transaction.api.v12.spec)
    compileOnly(libs.stax.ex)
    compileOnly(libs.txw2)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(
                listOf("src")
            )
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    from("src/META-INF/jboss-ejb3.xml") {
        into("META-INF")
    }
}

tasks.processTestResources {
    from("${rootProject.projectDir}/modules/common/resources"){
        include("log4j-test.xml")
        rename("log4j-test.xml", "log4j.xml")
    }
    into("build/resources/test/")
}