import java.util.Properties

val props: Properties = Properties().apply {
    val propertiesFilePath = "${rootProject.projectDir}/conf/database.properties"
    if (file(propertiesFilePath).exists()) {
        load(file(propertiesFilePath).inputStream())
    } else {
        load(file(propertiesFilePath + ".sample").inputStream())
    }
}
val dialectMap = mapOf(
    "db2" to "org.hibernate.dialect.DB2Dialect",
    "derby" to "org.hibernate.dialect.DerbyDialect",
    "hsqldb" to "org.hibernate.dialect.HSQLDialect",
    "h2" to "org.hibernate.dialect.H2Dialect",
    "informix" to "org.hibernate.community.dialect.InformixDialect",
    "ingres" to "org.hibernate.community.dialect.IngresDialect",
    "mssql" to "org.hibernate.dialect.SQLServerDialect",
    "oracle" to "org.hibernate.dialect.OracleDialect",
    "postgres" to "org.hibernate.dialect.PostgreSQLDialect",
    "sybase" to "org.hibernate.dialect.SybaseDialect"
)

val databaseName = props.getProperty("database.name", "mysql")
val dialect = dialectMap[databaseName]

if (dialect != null) {
    props.setProperty("hibernate.dialect", dialect)
} else if (databaseName != "mysql") {
    throw IllegalArgumentException("Unsupported database type $databaseName")
}

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
    compileOnly(libs.x509.common.util)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(listOf("src"))
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
    from("resources") {
        include("orm-ejbca-mysql.xml")
        into("META-INF")
    }
    from("resources") {
        include("persistence-ds-template.xml")
        rename("persistence-ds-template.xml", "persistence.xml")
        into("META-INF")
        filter { line: String ->
            val hibernateDialect = props.getProperty("hibernate.dialect", "")
            line.replace("\${datasource.jndi-name-prefix}", "java:/")
                .replace("\${datasource.jndi-name}", props.getProperty("datasource.jndi-name", "EjbcaDS"))
                .replace("\${database.name}", props.getProperty("database.name", "mysql"))
                .replace("\${hibernate.dialect}", hibernateDialect)
        }
    }
}
