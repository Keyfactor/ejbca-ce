plugins {
    java
    application
}

application {
    mainClass.set("org.ejbca.database.DatabaseCli")
}

dependencies {
    implementation(project(":modules:ejbca-common"))
    implementation(project(":modules:ejbca-entity"))
    implementation(project(":modules:cesecore-common"))
    implementation(project(":modules:cesecore-entity"))
    implementation(project(":modules:cesecore-ejb-interface"))
    implementation(libs.jakartaee.api)
    implementation(libs.log4j.v12.api)
    implementation(libs.xstream)
    implementation(libs.bundles.bouncy.castle)
    implementation(libs.commons.configuration2)
    implementation(libs.commons.lang3)
    implementation(libs.hibernate.core)
    implementation(libs.hibernate.community.dialects)

    runtimeOnly(project(":modules:ejbca-common-web"))
    runtimeOnly(project(":modules:ejbca-ejb"))
    runtimeOnly(project(":modules:ejbca-ejb-interface"))
    runtimeOnly(libs.antlr4.runtime)
    runtimeOnly(libs.byte.buddy)
    runtimeOnly(libs.cert.cvc)
    runtimeOnly(libs.classgraph)
    runtimeOnly(libs.classmate)
    runtimeOnly(libs.commons.beanutils)
    runtimeOnly(libs.commons.codec)
    runtimeOnly(libs.commons.collections4)
    runtimeOnly(libs.commons.fileupload2)
    runtimeOnly(libs.commons.fileupload2.core)
    runtimeOnly(libs.commons.io)
    runtimeOnly(libs.commons.lang)
    runtimeOnly(libs.commons.logging)
    runtimeOnly(libs.commons.text)
    runtimeOnly(libs.cryptotokens.api)
    runtimeOnly(libs.cryptotokens.impl)
    runtimeOnly(libs.cryptotokens.impl.ee)
    runtimeOnly(libs.fastInfoset)
    runtimeOnly(libs.hibernate.commons.annotations)
    runtimeOnly(libs.istack.commons.runtime.old)
    runtimeOnly(libs.jacknji11)
    runtimeOnly(libs.jackson.jakarta.rs.base)
    runtimeOnly(libs.jackson.jakarta.rs.json.provider)
    runtimeOnly(libs.jackson.module.jaxb.annotations)
    runtimeOnly(libs.jakarta.activation.api)
    runtimeOnly(libs.jakarta.persistence.api)
    runtimeOnly(libs.jakarta.servlet.api)
    runtimeOnly(libs.jakarta.xml.bind.api)
    runtimeOnly(libs.jandex)
    runtimeOnly(libs.javassist)
    runtimeOnly(libs.jaxb.core)
    runtimeOnly(libs.jaxb.runtime)
    runtimeOnly(libs.jboss.logging)
    runtimeOnly(libs.jboss.threads)
    runtimeOnly(libs.jboss.transaction.api.v12.spec)
    runtimeOnly(libs.jcip.annotations)
    runtimeOnly(libs.jldap)
    runtimeOnly(libs.jna)
    runtimeOnly(libs.json.patch)
    runtimeOnly(libs.keyfactor.commons.cli)
    runtimeOnly(libs.log4j.api)
    runtimeOnly(libs.log4j.core)
    runtimeOnly(libs.nimbus.jose.jwt)
    runtimeOnly(libs.p11ng)
    runtimeOnly(libs.parsson)
    runtimeOnly(libs.reactive.streams)
    runtimeOnly(libs.reflections)
    runtimeOnly(libs.resteasy.client)
    runtimeOnly(libs.resteasy.client.api)
    runtimeOnly(libs.resteasy.core)
    runtimeOnly(libs.resteasy.core.spi)
    runtimeOnly(libs.resteasy.jackson2.provider)
    runtimeOnly(libs.resteasy.multipart.provider)
    runtimeOnly(libs.resteasy.undertow)
    runtimeOnly(libs.stax.ex)
    runtimeOnly(libs.swagger.annotations)
    runtimeOnly(libs.swagger.core)
    runtimeOnly(libs.swagger.integration)
    runtimeOnly(libs.swagger.jaxrs)
    runtimeOnly(libs.swagger.models)
    runtimeOnly(libs.txw2)
    runtimeOnly(libs.undertow.core)
    runtimeOnly(libs.undertow.servlet)
    runtimeOnly(libs.wildfly.common)
    runtimeOnly(libs.x509.common.util)
    runtimeOnly(libs.xmlpull)
    runtimeOnly(libs.xnio.api)
    runtimeOnly(libs.xnio.nio)
    runtimeOnly(libs.xpp3.min)
    runtimeOnly(libs.yasson)
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("../src-cli"))
        }
    }
}

// define interfaces that should be used to generate service manifest files
ext["serviceInterfaces"] = listOf(
    "org.ejbca.database.CliCommandPlugin"
)


tasks.jar {
    archiveFileName.set("ejbca-db-cli.jar")

    from("${project.rootDir}/modules/ejbca-entity/resources/") {
        exclude("log4j*", "*-template.xml")
        include("*.xml")
        into("META-INF")
    }


    manifest {
        val versionString = project.extra["ejbcaVersionString"] as String
        val runtimeClasspath = configurations.runtimeClasspath.get().joinToString(" ") { "lib/${it.name}" }

        attributes(
            "Implementation-Version" to versionString,
            "Main-Class" to "org.ejbca.database.DatabaseCli",
            "Class-Path" to "$runtimeClasspath ./"
        )
    }
}


tasks.register<Copy>("packageCliDistributionFiles") {
    group = "build"
    description = "Packages the CLI JAR and its dependencies into the project's distribution directory."
    val distDir = File("${project.rootDir}/dist/ejbca-db-cli")

    // JAR file produced by the `jar` task
    from(tasks.jar.get().archiveFile)

    // runtime libraries
    from(configurations.runtimeClasspath) {
        into("lib")
    }

    // Copy other required files to the distribution directory
    from("${project.rootDir}/modules/ejbca-entity/resources/run.sh")
    from("${project.rootDir}/modules/ejbca-entity/resources/run.bat")

    from("${project.rootDir}/modules/common/resources") {
        include("log4j-cli.xml")
        rename("log4j-cli.xml", "log4j.xml")
    }

    from("${project.rootDir}/modules/ejbca-entity/resources/persistence-cli-template.xml") {
        into("META-INF")
        rename { "persistence.xml" }
    }

    // extra properties and configuration files
    from("${project.rootDir}/conf") {
        include("databaseprotection.properties")
        into("conf")
    }

    mkdir("${distDir}/endorsed")

    into(distDir)
}


tasks.build {
    logger.lifecycle("Building DB CLI for EJBCA ${project.version}")
    finalizedBy("packageCliDistributionFiles")
}
