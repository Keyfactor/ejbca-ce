import org.apache.tools.ant.filters.ReplaceTokens

plugins {
    java
}

tasks.jar {
    from("${rootProject.projectDir}/src") {
        include("internal.properties")
        filter { line: String ->
            line.replace("#datasource.jndi-name-prefix=", "datasource.jndi-name-prefix=java:/")
        }
    }
    from("${rootProject.projectDir}") {
        include("conf/**/*.properties")
        exclude("conf/install.properties")
        exclude("conf/plugins")
        exclude("conf/batchtool.properties")
    }
    from("${rootProject.projectDir}/src/upgrade")
}
