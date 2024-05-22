import org.apache.tools.ant.filters.ReplaceTokens
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
    "informix" to "org.hibernate.dialect.InformixDialect",
    "ingres" to "org.hibernate.dialect.IngresDialect",
    "mssql" to "org.hibernate.dialect.SQLServer2008Dialect",
    "mysql" to "org.hibernate.dialect.MySQL5InnoDBDialect",
    "oracle" to "org.hibernate.dialect.Oracle10gDialect",
    "postgres" to "org.hibernate.dialect.PostgreSQLDialect",
    "sybase" to "org.hibernate.dialect.SybaseDialect"
)
val dialect = dialectMap[props.getProperty("database.name", "mysql")]
        ?: throw IllegalArgumentException("Unsupported database type ${props.getProperty("database.name")}")
props.setProperty("hibernate.dialect", dialect)

plugins {
    java
}

dependencies {
    compileOnly(project(":modules:ejbca-common"))
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(project(":modules:cesecore-entity"))
    compileOnly(libs.java.ee.api)
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
            line.replace("\${datasource.jndi-name-prefix}", "java:/")
                .replace("\${datasource.jndi-name}", props.getProperty("datasource.jndi-name", "EjbcaDS"))
                .replace("\${database.name}", props.getProperty("database.name", "mysql"))
                .replace("\${hibernate.dialect}", props.getProperty("hibernate.dialect"))
        }
    }
}
