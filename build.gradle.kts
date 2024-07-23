import java.util.Properties

val props: Properties = Properties().apply {
    val propertiesFilePath = "conf/ejbca.properties"
    if (file(propertiesFilePath).exists()) {
        load(file(propertiesFilePath).inputStream())
    } else {
        load(file(propertiesFilePath + ".sample").inputStream())
    }
}

// Specify what edition you want to build by passing -Pedition=ee or =ce (default: ee)
val editionProp = providers.gradleProperty("edition").getOrElse("ee")
val eeModuleExists = file("modules/edition-specific-ee").exists()
val edition = if (editionProp == "ce" || !eeModuleExists) "ce" else "ee"

allprojects {
    repositories {
        flatDir {
            dirs(rootProject.projectDir.resolve("lib"))
            dirs(rootProject.projectDir.resolve("lib/jee"))
            dirs(rootProject.projectDir.resolve("lib/ext"))
            dirs(rootProject.projectDir.resolve("lib/hibernate"))
            dirs(rootProject.projectDir.resolve("lib/xstream"))
            dirs(rootProject.projectDir.resolve("lib/jee/soapclient"))
            dirs(rootProject.projectDir.resolve("lib/ext/jackson2"))
            dirs(rootProject.projectDir.resolve("lib/swagger"))
            dirs(rootProject.projectDir.resolve("lib/ext/swagger"))
            dirs(rootProject.projectDir.resolve("lib/primefaces"))
            dirs(rootProject.projectDir.resolve("lib/ct"))
        }
    }
    extra["edition"] = edition
}

plugins {
    ear
}

configurations {
    // Custom configuration for jar files that are both modules and lib
    create("earlibanddeploy")
}


dependencies {
    "earlibanddeploy"(project(path = ":modules:ejbca-ejb", configuration = "archives"))
    deploy(project(path = ":modules:cesecore-ejb", configuration = "archives"))
    deploy(project(path = ":modules:ejbca-ws", configuration = "archives"))
    deploy(project(path = ":modules:admin-gui", configuration = "archives"))
    deploy(project(path = ":modules:ejbca-cmp-war", configuration = "archives"))
    deploy(project(path = ":modules:ejbca-scep-war", configuration = "archives"))
    deploy(project(path = ":modules:healthcheck-war", configuration = "archives"))
    deploy(project(path = ":modules:clearcache-war", configuration = "archives"))
    deploy(project(path = ":modules:ejbca-webdist-war", configuration = "archives"))
    deploy(project(path = ":modules:va", configuration = "archives"))
    deploy(project(path = ":modules:certificatestore", configuration = "archives"))
    deploy(project(path = ":modules:crlstore", configuration = "archives"))
    deploy(project(path = ":modules:ra-gui", configuration = "archives"))
    if (edition == "ee") {
        "earlibanddeploy"(project(path = ":modules:edition-specific-ee", configuration = "archives"))
        deploy(project(path = ":modules:statedump:ejb", configuration = "archives"))
        deploy(project(path = ":modules:configdump:ejb", configuration = "archives"))
        deploy(project(path = ":modules:peerconnector:rar", configuration = "archives"))
        deploy(project(path = ":modules:peerconnector:war", configuration = "archives"))
        deploy(project(path = ":modules:peerconnector:ejb", configuration = "archives"))
        deploy(project(path = ":modules:acme", configuration = "archives"))
        deploy(project(path = ":modules:ssh:war", configuration = "archives"))
        deploy(project(path = ":modules:msae", configuration = "archives"))
        deploy(project(path = ":modules:cits", configuration = "archives"))
        deploy(project(path = ":modules:est", configuration = "archives"))
        deploy(project(path = ":modules:ejbca-rest-api", configuration = "archives"))
        earlib(project(path = ":modules:statedump:common", configuration = "archives"))
        earlib(project(path = ":modules:configdump:common", configuration = "archives"))
        earlib(project(path = ":modules:peerconnector:ra", configuration = "archives"))
        earlib(project(path = ":modules:peerconnector:publ", configuration = "archives"))
        earlib(project(path = ":modules:peerconnector:interface", configuration = "archives"))
        earlib(project(path = ":modules:peerconnector:common", configuration = "archives"))
        earlib(project(path = ":modules:plugins-ee", configuration = "archives"))
    }
    if (edition == "ce") {
        // When edition is CE we use :modules:edition-specific:ejb as a replacement for :modules:edition-specific-ee
        "earlibanddeploy"(project(path = ":modules:edition-specific:ejb", configuration="archives"))
    }
    if (edition == "ee" && !props.getProperty("ejbca.productionmode", "true").toBoolean()) {
        deploy(":swagger-ui@war")
    }
    if (!props.getProperty("ejbca.productionmode", "true").toBoolean()) {
        deploy(project(":modules:systemtests:ejb"))
    }
    // External libraries
    earlib(libs.bcpkix)
    earlib(libs.bcprov)
    earlib(libs.bctls)
    earlib(libs.bcutil)
    earlib(libs.cert.cvc)
    earlib(libs.jldap)
    earlib(libs.adsddl)
    earlib(libs.commons.beanutils)
    earlib(libs.commons.codec)
    earlib(libs.commons.collections4)
    earlib(libs.commons.configuration2)
    earlib(libs.commons.fileupload)
    earlib(libs.commons.io)
    earlib(libs.commons.lang)
    earlib(libs.commons.lang3)
    earlib(libs.commons.logging)
    earlib(libs.commons.text)
    earlib(libs.nimbus.jose.jwt)
    earlib(libs.httpclient)
    earlib(libs.httpcore)
    earlib(libs.httpmime)
    earlib(libs.json.simple)
    earlib(libs.jcip.annotations)
    earlib(libs.snakeyaml)
    earlib(libs.guava)
    earlib(libs.caffeine)
    earlib(libs.jsch)
    earlib(libs.jna)
    earlib(libs.kerb4j.server.common)
    earlib(libs.kerb.core)
    earlib(libs.kerby.asn1)
    earlib(libs.kerb.crypto)
    earlib(libs.x509.common.util)
    earlib(libs.cryptotokens.api)
    earlib(libs.cryptotokens.impl)
    earlib(libs.jacknji11)
    earlib(libs.log4j.v12.api)
    earlib(libs.log4j.api)
    earlib(libs.log4j.core)
    // Jackson
    earlib(libs.jackson.annotations)
    earlib(libs.jackson.core)
    earlib(libs.jackson.databind)
    earlib(libs.jackson.dataformat.yaml)
    // Xstream
    earlib(libs.xmlpull)
    earlib(libs.xpp3.min)
    earlib(libs.xstream)
    // Internally generated WS files
    earlib(libs.ejbca.ws.client.gen)
    // EE Only external libraries
    if (edition == "ee") {
        earlib(libs.ctlog)
        earlib(libs.dnsjava)
        earlib(libs.protobuf.java)
        earlib(libs.p11ng)
        earlib(libs.cryptotokens.impl)
    }
    // Internal modules packaged as libraries
    earlib(project(path = ":modules:cesecore-common", configuration = "archives"))
    earlib(project(path = ":modules:cesecore-entity", configuration = "archives"))
    earlib(project(path = ":modules:cesecore-ejb-interface", configuration = "archives"))
    earlib(project(path = ":modules:cesecore-x509ca", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-common", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-common-web", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-ejb-interface", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-entity", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-ws:common", configuration = "archives"))
    earlib(project(path = ":modules:va:extensions", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-properties", configuration = "archives"))
    earlib(project(path = ":modules:edition-specific:interface", configuration = "archives"))
    earlib(project(path = ":modules:plugins", configuration = "archives"))
    earlib(project(path = ":modules:ejbca-ws-cli", configuration = "archives"))
    if (edition == "ee") {
        earlib(project(path = ":modules:cesecore-cvcca", configuration = "archives"))
        earlib(project(path = ":modules:acme:common", configuration = "archives"))
        earlib(project(path = ":modules:ssh:common", configuration = "archives"))
        earlib(project(path = ":modules:cits:common", configuration = "archives"))
        earlib(project(path = ":modules:proxy-ca", configuration = "archives"))
        earlib(project(path = ":modules:caa", configuration = "archives"))
        earlib(project(path = ":modules:ct", configuration = "archives"))
    }
    if (!props.getProperty("ejbca.productionmode", "true").toBoolean()) {
        "earlibanddeploy"(project(":modules:systemtests:common"))
        earlib(project(":modules:systemtests:interface"))
    }
}

tasks.ear {
    generateDeploymentDescriptor = false
    from("src/deploy/ear/META-INF") {
        include("application.xml")
        filter { line: String ->
            line.replace("<!--@status.war@-->", "<module><web><web-uri>status.war</web-uri><context-root>/ejbca/publicweb/status</context-root></web></module>")
                    .replace("<!--@certstore.war@-->", "<module><web><web-uri>certstore.war</web-uri><context-root>/ejbca/publicweb/certificates</context-root></web></module>")
                    .replace("<!--@crlstore.war@-->", "<module><web><web-uri>crlstore.war</web-uri><context-root>/ejbca/publicweb/crls</context-root></web></module>")
                    .replace("<!--@ejbca-ws-ejb.jar@-->", "<module><ejb>ejbca-ws-ejb.jar</ejb></module>")
                    .replace("<!--@ra-gui.war@-->", "<module><web><web-uri>ra-gui.war</web-uri><context-root>/ejbca/ra</context-root></web></module>")
        }
        if (edition == "ee") {
            filter { line: String ->
                line.replace("<!--@status.war@-->", "<module><web><web-uri>status.war</web-uri><context-root>/ejbca/publicweb/status</context-root></web></module>")
                        .replace("<!--@statedump-ejb.jar@-->", "<module><ejb>statedump-ejb.jar</ejb></module>")
                        .replace("<!--@configdump-ejb.jar@-->", "<module><ejb>configdump-ejb.jar</ejb></module>")
                        .replace("<!--@peerconnector-ejb.jar@-->", "<module><ejb>peerconnector-ejb.jar</ejb></module>")
                        .replace("<!--@peerconnector.rar@-->", "<module><connector>peerconnector.rar</connector></module>")
                        .replace("<!--@peerconnector.war@-->", "<module><web><web-uri>peerconnector.war</web-uri><context-root>/ejbca/peer</context-root></web></module>")
                        .replace("<!--@ejbca-rest-api.war@-->", "<module><web><web-uri>ejbca-rest-api.war</web-uri><context-root>/ejbca/ejbca-rest-api</context-root></web></module>")
                        .replace("<!--@acme.war@-->", "<module><web><web-uri>acme.war</web-uri><context-root>/ejbca/acme</context-root></web></module>")
                        .replace("<!--@msae.war@-->", "<module><web><web-uri>msae.war</web-uri><context-root>/ejbca/msae</context-root></web></module>")
                        .replace("<!--@est.war@-->", "<module><web><web-uri>est.war</web-uri><context-root>/.well-known/est</context-root></web></module>")
                        .replace("<!--@ssh.war@-->", "<module><web><web-uri>ssh.war</web-uri><context-root>/ejbca/ssh</context-root></web></module>")
                        .replace("<!--@swagger-ui.war@-->", "<module><web><web-uri>swagger-ui.war</web-uri><context-root>/ejbca/swagger-ui</context-root></web></module>")
                        .replace("<!--@cits.war@-->", "<module><web><web-uri>cits.war</web-uri><context-root>/ejbca/its</context-root></web></module>")
            }
        }
        if (!props.getProperty("ejbca.productionmode", "true").toBoolean()) {
            filter { line: String ->
                line.replace("<!--@ejbca-systemtest-ejb.jar@-->", "<module><ejb>systemtests-ejb.jar</ejb></module>")
            }
        }
        include("jboss-deployment-structure.xml")
        include("services/*")
        into("META-INF")
    }
    from(configurations["earlibanddeploy"]) {
        into("lib")
    }
    from(configurations["earlibanddeploy"]) {
        into("/")
    }
}

task<Copy>("deployear") {
    dependsOn("ear")
    val appServerHome = System.getenv("APPSRV_HOME")
    doFirst {
        if (appServerHome == null) {
            throw GradleException("APPSRV_HOME environment variable is not set.")
        }
    }
    from(layout.buildDirectory.file("libs/ejbca.ear"))
    into("$appServerHome/standalone/deployments")
    doLast {
        println("Deployed EAR to application server at $appServerHome")
    }
}

// Import all Ant targets from build.xml and make them available as Gradle tasks.
// NOTE: This is a migration convenience that should gradually be phased out in favor of native Gradle tasks.
ant.importBuild("$projectDir/build.xml") { antTargetName ->
    // append "-ant" to Ant targets whoese names match existing Gradle tasks
    val overlapingTargetNames = arrayOf("build", "clean", "deployear")
    if (antTargetName in overlapingTargetNames) {
        antTargetName + "-ant"
    } else {
        // Gradle doesn't allow task names to contain the ":" character, so let's remap Ant tasks that contain it.
        antTargetName.replace(":", "-")
    }
}