import java.net.Socket
import org.gradle.internal.os.OperatingSystem
import java.io.ByteArrayOutputStream

val edition: String by extra
val appServerHome: String? by extra
val isProductionMode: Boolean by extra

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
            dirs(rootProject.projectDir.resolve("lib/ext/test"))
            dirs(rootProject.projectDir.resolve("lib/ext/resteasy-jaxrs-lib"))
            dirs(rootProject.projectDir.resolve("lib/ext/wsgen"))
        }
    }
}

// add the directory containing 'jboss-client.jar' to the list of library repositories
if (!isProductionMode) {
    if (appServerHome == null) {
        throw GradleException(
            """
                📣 To build EJBCA in non-production mode ('ejbca.productionmode=false'), 
                you must first configure the application server's home directory.
                
                You can do this by either setting an 'APPSRV_HOME' environment variable 
                or by configuring the 'appserver.home' property in the 'conf/ejbca.properties' file.
            """.trimIndent()
        )
    }
    allprojects {
        repositories {
            flatDir {
                dirs(file("$appServerHome/bin/client"))
            }
        }
    }
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
    deploy(project(path = ":modules:ejbca-rest-api", configuration = "archives"))


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
        "earlibanddeploy"(project(path = ":modules:edition-specific:ejb", configuration = "archives"))
    }
    if (!isProductionMode) {
        deploy(":swagger-ui@war")
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
    earlib(libs.commons.fileupload2)
    earlib(libs.commons.fileupload2.core)
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
        earlib(libs.cryptotokens.impl.ee)
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
        earlib(project(path = ":modules:mpic", configuration = "archives"))
        earlib(project(path = ":modules:ct", configuration = "archives"))
        earlib(project(path = ":modules:iodef", configuration = "archives"))
        earlib(project(path = ":modules:mpic", configuration = "archives"))
    }
    if (!isProductionMode) {
        "earlibanddeploy"(project(":modules:systemtests:common"))
        earlib(project(":modules:systemtests:interface"))
    }
}

tasks.ear {
    generateDeploymentDescriptor = false
    from("src/deploy/ear/META-INF") {
        include("application.xml")
        filter { line: String ->
            line
                .replace(
                    "<!--@status.war@-->",
                    "<module><web><web-uri>status.war</web-uri><context-root>/ejbca/publicweb/status</context-root></web></module>"
                )
                .replace(
                    "<!--@certstore.war@-->",
                    "<module><web><web-uri>certstore.war</web-uri><context-root>/ejbca/publicweb/certificates</context-root></web></module>"
                )
                .replace(
                    "<!--@crlstore.war@-->",
                    "<module><web><web-uri>crlstore.war</web-uri><context-root>/ejbca/publicweb/crls</context-root></web></module>"
                )
                .replace(
                    "<!--@ra-gui.war@-->",
                    "<module><web><web-uri>ra-gui.war</web-uri><context-root>/ejbca/ra</context-root></web></module>"
                )
                .replace(
                    "<!--@ejbca-rest-api.war@-->",
                    "<module><web><web-uri>ejbca-rest-api.war</web-uri><context-root>/ejbca/ejbca-rest-api</context-root></web></module>"
                )
        }
        if (edition == "ee") {
            filter { line: String ->
                line.replace(
                    "<!--@status.war@-->",
                    "<module><web><web-uri>status.war</web-uri><context-root>/ejbca/publicweb/status</context-root></web></module>"
                )
                    .replace("<!--@statedump-ejb.jar@-->", "<module><ejb>statedump-ejb.jar</ejb></module>")
                    .replace("<!--@configdump-ejb.jar@-->", "<module><ejb>configdump-ejb.jar</ejb></module>")
                    .replace("<!--@peerconnector-ejb.jar@-->", "<module><ejb>peerconnector-ejb.jar</ejb></module>")
                    .replace("<!--@peerconnector.rar@-->", "<module><connector>peerconnector.rar</connector></module>")
                    .replace(
                        "<!--@peerconnector.war@-->",
                        "<module><web><web-uri>peerconnector.war</web-uri><context-root>/ejbca/peer</context-root></web></module>"
                    )
                    .replace(
                        "<!--@acme.war@-->",
                        "<module><web><web-uri>acme.war</web-uri><context-root>/ejbca/acme</context-root></web></module>"
                    )
                    .replace(
                        "<!--@msae.war@-->",
                        "<module><web><web-uri>msae.war</web-uri><context-root>/ejbca/msae</context-root></web></module>"
                    )
                    .replace(
                        "<!--@est.war@-->",
                        "<module><web><web-uri>est.war</web-uri><context-root>/.well-known/est</context-root></web></module>"
                    )
                    .replace(
                        "<!--@ssh.war@-->",
                        "<module><web><web-uri>ssh.war</web-uri><context-root>/ejbca/ssh</context-root></web></module>"
                    )
                    .replace(
                        "<!--@cits.war@-->",
                        "<module><web><web-uri>cits.war</web-uri><context-root>/ejbca/its</context-root></web></module>"
                    )
            }
        }
        if (!isProductionMode) {
            filter { line: String ->
                line.replace("<!--@ejbca-systemtest-ejb.jar@-->", "<module><ejb>systemtests-ejb.jar</ejb></module>")
                    .replace(
                        "<!--@swagger-ui.war@-->",
                        "<module><web><web-uri>swagger-ui.war</web-uri><context-root>/ejbca/swagger-ui</context-root></web></module>"
                    )
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
    doFirst {
        if (appServerHome == null) {
            throw GradleException(
                """
                    📣 Unknown application server's home directory. Please set an 'APPSRV_HOME' environment variable 
                    or configure the 'appserver.home' property in the 'conf/ejbca.properties' file.
                """.trimIndent()
            )
        }
    }
    from(layout.buildDirectory.file("libs/ejbca.ear"))
    into("$appServerHome/standalone/deployments")
    doLast {
        println("Deployed EAR to application server at $appServerHome")
    }
}

subprojects {
    // Add common test configuration to all modules/subprojects containing test sources
    if (file("src-test").exists()) {
        plugins.apply("java")

        // Unit tests
        tasks.withType<Test> {
            description = "Runs unit tests."

            filter {
                includeTestsMatching("*UnitTest")
                isFailOnNoMatchingTests = false
            }

            java {
                sourceSets["test"].java.srcDirs("src-test")
                sourceSets["test"].compileClasspath += sourceSets["main"].compileClasspath
                sourceSets["test"].runtimeClasspath += sourceSets["main"].compileClasspath
            }
        }

        // System tests
        val systemTestsExist = fileTree("src-test").apply {
            include("**/*SystemTest.java")
        }.toList().isNotEmpty()

        // We can reduce the number of Gradle tasks and configurations offered by IDEs for test execution
        // by adding a systemTest task only if the module contains any system test classes.
        if (systemTestsExist) {
            tasks.register<Test>("systemTest") {
                description = "Runs system tests."
                group = "verification"
                forkEvery = 1
                maxParallelForks = 1

                dependsOn(":checkIfAppServerIsRunning")
                shouldRunAfter("test")

                filter {
                    includeTestsMatching("*SystemTest")
                    excludeTestsMatching("*UnitTest")
                    isFailOnNoMatchingTests = false
                }

                // Since our system test classes live alongside unit tests in the "src-test" directory,
                // we can reuse the source configuration of the "test" task.
                testClassesDirs = sourceSets["test"].output.classesDirs
                classpath = sourceSets["test"].runtimeClasspath

                onlyIf {
                    if (isProductionMode) {
                        logger.lifecycle("You can't run system tests in production mode.")
                    }
                    !isProductionMode
                }
            }

            // Add common system test dependencies.
            dependencies {
                val testRuntimeOnly by configurations
                testRuntimeOnly(rootProject.libs.jboss.logging)

                if (!isProductionMode) {
                    // `:jboss:client` is used instead of `rootProject.libs.jboss.client`
                    // to prevent Gradle from prematurely resolving the non-existent library
                    // when `isProductionMode` is set to true
                    testRuntimeOnly(":jboss:client")
                }
            }
        }

        // Add common dependencies used by most tests.
        dependencies {
            val testImplementation by configurations
            testImplementation(rootProject.libs.bundles.utils)
            testImplementation(rootProject.libs.bundles.test)
        }

        // Configure test tasks to output some basic information about executed tests
        tasks.withType(Test::class) {
            doLast {
                // print module's report location
                val reportDir = reports.html.outputLocation.get().asFile.absolutePath
                val separator = File.separator
                logger.lifecycle("'${project.name}' test report: file:${separator}${separator}$reportDir${separator}index.html")
            }
            // print a summary derived from all test reports
            finalizedBy(":summarizeTestResults")
        }
    }
}

// If system tests in certain modules are executed before others, they cause test failures in unrelated modules.
// This should be fixed, but for now, we can work around the issue by enforcing the same order as used in Ant.
val systemTestTasksOrder = listOfNotNull(
    project.findProject(":modules:systemtests")?.tasks?.named("systemTest"),
    project.findProject(":modules:ejbca-ws")?.tasks?.named("systemTest"),
    project.findProject(":modules:statedump")?.tasks?.named("systemTest"),
    project.findProject(":modules:peerconnector")?.tasks?.named("systemTest"),
    project.findProject(":modules:plugins")?.tasks?.named("systemTest"),
    project.findProject(":modules:plugins-ee")?.tasks?.named("systemTest"),
    project.findProject(":modules:acme")?.tasks?.named("systemTest"),
    project.findProject(":modules:ejbca-rest-api")?.tasks?.named("systemTest"),
    project.findProject(":modules:caa")?.tasks?.named("systemTest"),
    project.findProject(":modules:mpic")?.tasks?.named("systemTest"),
    project.findProject(":modules:ssh")?.tasks?.named("systemTest"),
    project.findProject(":modules:cits")?.tasks?.named("systemTest"),
    project.findProject(":modules:ejbca-entity")?.tasks?.named("systemTest")
)

// Add mustRunAfter dependencies to systemTest tasks to enforce the "correct order".
for (i in 1 until systemTestTasksOrder.size) {
    val previousTasks = systemTestTasksOrder.subList(0, i)
    val currentTask = systemTestTasksOrder[i]

    currentTask.configure {
        mustRunAfter(previousTasks)
    }
}

// TODO ECA-12541: Replace with an aggregated test report
tasks.register("summarizeTestResults") {
    description = "Summarizes the test results of all subprojects."
    group = "reporting"

    doLast {
        val documentBuilderFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        val documentBuilder = documentBuilderFactory.newDocumentBuilder()
        val xPath = javax.xml.xpath.XPathFactory.newInstance().newXPath()

        val executedTestTasks = gradle.taskGraph.allTasks.filterIsInstance<Test>()

        val testResultDirectories = executedTestTasks.flatMap { testTask ->
            testTask.project.fileTree(testTask.project.layout.buildDirectory) {
                include("**/test-results/**/*.xml")
            }.files
        }

        var totalExecuted = 0
        var totalPassed = 0
        var totalFailed = 0
        var totalSkipped = 0

        testResultDirectories.forEach { file ->
            val document = documentBuilder.parse(file)
            val testCases = xPath.compile("//testcase")
                .evaluate(document, javax.xml.xpath.XPathConstants.NODESET) as org.w3c.dom.NodeList
            totalExecuted += testCases.length
            for (i in 0 until testCases.length) {
                val testCase = testCases.item(i)
                val failure = xPath.compile("failure").evaluate(testCase, javax.xml.xpath.XPathConstants.NODE)
                val skipped = xPath.compile("skipped").evaluate(testCase, javax.xml.xpath.XPathConstants.NODE)
                when {
                    failure != null -> totalFailed++
                    skipped != null -> totalSkipped++
                    else -> totalPassed++
                }
            }
        }

        logger.lifecycle("Test summary: $totalExecuted executed, $totalPassed passed, $totalFailed failed, $totalSkipped skipped.")
    }
}

tasks.register("checkIfAppServerIsRunning") {
    description = "Checks whether an application server is running. Used to determine if system tests can be executed."
    group = "verification"
    doLast {
        val host = findProperty("target.hostname") as String? ?: "localhost"
        val port = findProperty("target.port.https") as String? ?: "8443"
        try {
            Socket(host, port.toInt()).use { true }
        } catch (e: Exception) {
            throw GradleException(
                """
                    📣 The application server does not appear to be running on '$host' port '$port'.
                    Please start it to run system tests.
                """.trimIndent()
            )
        }
    }
}

tasks.register<Delete>("cleanDist") {
    description = "Deletes the dist directory."
    group = "build"
    var distDir = file("${rootProject.rootDir}/dist")
    if (distDir.exists()) {
        distDir.deleteRecursively()
    }
}

tasks.named("clean") {
    dependsOn("cleanDist")
}

// Git hook setup
tasks.register("configureGitHooks") {
    description = "Configures Git hooks."
    group = "build"
    doFirst {
        // Skip Git hook setup on Windows systems. Most of our hooks perform simple checks using Unix tools,
        // which are likely to encounter issues when executed in Git Bash on Windows.
        if (OperatingSystem.current().isWindows) {
            return@doFirst
        }

        // Verify that required directories are present.
        val gitDir = project.file(".git") // won't exist in Zip distributions
        val ciDir = project.file("src/ci") // won't exist in CE

        if (!gitDir.isDirectory || !ciDir.isDirectory) {
            return@doFirst
        }

        // Check the user's local Git config and update the project's hook path if needed.
        val expectedGitHookPath = "src/ci/git-hooks"
        val currentGitHookPath = ByteArrayOutputStream().use { output ->
            exec {
                commandLine("git", "config", "--local", "--get", "core.hooksPath")
                standardOutput = output
                isIgnoreExitValue = true
            }
            output.toString().trim().takeIf { it.isNotEmpty() }
        }

        if (currentGitHookPath != expectedGitHookPath) {
            exec {
                commandLine("git", "config", "--local", "--replace-all", "core.hooksPath", expectedGitHookPath)
            }
            logger.lifecycle("⚙\uFE0F Configured Git to use hooks located in '$expectedGitHookPath'.")
        }
    }
}

tasks.named("build") {
    dependsOn("configureGitHooks")
}