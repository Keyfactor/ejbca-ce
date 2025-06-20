plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(libs.jakartaee.api)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.x509.common.util)

    testRuntimeOnly(libs.bundles.xstream)
    testImplementation(libs.bundles.bouncy.castle)

    if (project.extra["edition"] == "ee") {
        testImplementation(project(":modules:ejbca-entity:cli"))
    }
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.systemTest {
    filter {
        // TODO ECA-12480: Create custom test tasks similar to Ant's "test-dbschema" and "test-ocspmon" targets.
        val includeDbSchema = providers.gradleProperty("includeDbSchema")
        if (!includeDbSchema.isPresent || includeDbSchema.get() == "false") {
            excludeTestsMatching("DatabaseSchemaSystemTest")
        }
        val includeOcspMonitoringTool = providers.gradleProperty("includeOcspMonitoringTool")
        if (!includeOcspMonitoringTool.isPresent || includeOcspMonitoringTool.get() == "false") {
            excludeTestsMatching("OcspMonitoringToolSystemTest")
        }
    }
}

tasks.processTestResources {
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    from(sourceSets["test"].allSource){
        include("**/test.xml")
    }
    into("${layout.buildDirectory}/resources/test/")
}

tasks.jar {
    val jndiName = findProperty("datasource.jndi-name") as String? ?: "EjbcaDS"
    val databaseName = findProperty("database.name") as String? ?: "mysql"

    from(sourceSets["main"].output)
    from("resources") {
        include("orm-ejbca-$databaseName.xml")
        into("META-INF")
    }
    from("resources") {
        include("persistence-ds-template.xml")
        rename("persistence-ds-template.xml", "persistence.xml")
        into("META-INF")
        filter { line: String ->
            line.replace("\${datasource.jndi-name-prefix}", "java:/")
                .replace("\${datasource.jndi-name}", jndiName)
                .replace("\${database.name}", databaseName)
        }
    }
}
