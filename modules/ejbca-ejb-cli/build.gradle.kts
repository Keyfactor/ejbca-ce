plugins {
    java
    application
}

val appServerHome: String? by extra

application {
    mainClass.set("org.ejbca.ui.cli.EjbcaEjbCli")
}

dependencies {
    implementation(project(":modules:cesecore-common"))
    implementation(project(":modules:cesecore-ejb-interface"))
    implementation(project(":modules:cesecore-entity"))
    implementation(project(":modules:ejbca-ejb-interface"))
    implementation(project(":modules:ejbca-entity"))
    implementation(project(":modules:ejbca-common"))
    implementation(libs.bundles.bouncy.castle)
    implementation(libs.cert.cvc)
    implementation(libs.commons.beanutils)
    implementation(libs.commons.collections4)
    implementation(libs.commons.configuration2)
    implementation(libs.commons.io)
    implementation(libs.commons.lang3)
    implementation(libs.bundles.cryptotokens)
    implementation(libs.jakartaee.api)
    implementation(libs.keyfactor.commons.cli)
    implementation(libs.log4j.v12.api)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.x509.common.util)

    runtimeOnly(libs.bundles.xstream)
    runtimeOnly(libs.bundles.jacknji)
    runtimeOnly(libs.bundles.log4j)

    runtimeOnly(libs.commons.logging)
    runtimeOnly(libs.commons.text)
    runtimeOnly(libs.antlr4.runtime)
    runtimeOnly(libs.byte.buddy)
    runtimeOnly(libs.classmate)
    runtimeOnly(libs.fastInfoset)
    runtimeOnly(libs.hibernate.core)
    runtimeOnly(libs.hibernate.commons.annotations)
    runtimeOnly(libs.hibernate.community.dialects)
    runtimeOnly(libs.httpcore)
    runtimeOnly(libs.httpclient)
    runtimeOnly(libs.httpmime)
    runtimeOnly(libs.istack.commons.runtime.old)
    runtimeOnly(libs.jakarta.activation.api)
    runtimeOnly(libs.jakarta.persistence.api)
    runtimeOnly(libs.jakarta.xml.bind.api)
    runtimeOnly(libs.jandex)
    runtimeOnly(libs.javassist)
    runtimeOnly(libs.jaxb.runtime)

    runtimeOnly(libs.jboss.transaction.api.v12.spec)
    runtimeOnly(libs.jcip.annotations)
    runtimeOnly(libs.jldap)
    runtimeOnly(libs.json.simple)
    runtimeOnly(libs.slf4j.reload4j)
    runtimeOnly(libs.stax.ex)
    runtimeOnly(libs.txw2)

    runtimeOnly(project(":modules:plugins"))

    if (project.extra["edition"] == "ee") {
        implementation(libs.p11ng)

        runtimeOnly(project(":modules:plugins-ee"))
        runtimeOnly(project(":modules:peerconnector:common"))
        runtimeOnly(project(":modules:peerconnector:interface"))
        runtimeOnly(project(":modules:peerconnector:publ"))
        runtimeOnly(project(":modules:peerconnector:cli"))
    }

    if (appServerHome != null) {
        runtimeOnly(":jboss:client")
    } else {
        logger.warn(
            "⚠\uFE0F The JBoss client library is not included in this build. " +
                    "ConfigDump CLI will be unable to interact with the application server."
        )
    }
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
    "org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin"
)

tasks.jar {
    manifest {
        val versionString = project.extra["ejbcaVersionString"] as String
        val runtimeClasspath = configurations.runtimeClasspath.get().joinToString(" ") { "lib/${it.name}" }

        attributes(
            "Implementation-Version" to versionString,
            "Main-Class" to "org.ejbca.ui.cli.EjbcaEjbCli",
            "Class-Path" to "$runtimeClasspath ./"
        )
    }

    // extra properties and configuration files
    from("${project.rootDir}/conf") {
        include("ejbca.properties")
        include("cesecore.properties")
        into("conf")
    }

    from("${project.rootDir}/src/java") {
        include("defaultvalues.properties")
    }

    // exclude unnecessary files in the resources directory from being added to the JAR file
    exclude("**/*.sh")
}

tasks.register<Copy>("packageCliDistributionFiles") {
    group = "build"
    description = "Packages the CLI JAR and its dependencies into the project's distribution directory."
    val distDir = File("${project.rootDir}/dist/ejbca-ejb-cli")

    // JAR file produced by the `jar` task
    from(tasks.jar.get().archiveFile)

    // runtime libraries
    from(configurations.runtimeClasspath) {
        into("lib")
    }

    from("${project.rootDir}/src/intresources") {
        into("intresources")
    }

    // Copy other required files to the distribution directory
    from("${project.rootDir}/conf") {
        include("batchtool.properties")
    }

    from("${project.rootDir}/src/appserver/jboss/jboss7") {
        include("jboss-ejb-client.properties")
    }

    from("${project.rootDir}/conf") {
        include("jndi.properties.jboss7")
        rename("jndi.properties.jboss7", "jndi.properties")
    }

    from("${project.rootDir}/modules/common/resources") {
        include("log4j-cli.xml")
        rename("log4j-cli.xml", "log4j.xml")
    }

    into(distDir)
}

tasks.build {
    logger.lifecycle("Building remote EJB access CLI for EJBCA ${project.version}")
    finalizedBy("packageCliDistributionFiles")
}