rootProject.name = "ejbca"
val editionProp = providers.gradleProperty("edition").getOrElse("ee")
val eeModuleExists = file("modules/edition-specific-ee").exists()
val edition = if (editionProp == "ce" || !eeModuleExists) "ce" else "ee"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            library("bcprov", ":bcprov:jdk18on-1.79")
            library("bcpkix", ":bcpkix:jdk18on-1.79")
            library("bctls", ":bctls:jdk18on-1.79")
            library("bcutil", ":bcutil:jdk18on-1.79")
            library("ejbca-ws-client-gen", ":ejbca-ws-client-gen:1")
            library("caffeine", ":caffeine:3.1.6")
            library("jakartaee-api", ":jakarta.jakartaee-api:10.0.0")
            library("jakarta.xml.ws-api", ":jakarta.xml.ws-api:4.0.1")
            library("jaxb-runtime", ":jaxb-runtime:4.0.5")
            library("cert-cvc", ":cert-cvc:1.6.2")
            library("guava", ":guava:33.0.0-jre")
            library("log4j-v12-api", ":log4j-1.2-api:2.20.0")
            library("log4j-api", ":log4j-api:2.20.0")
            library("log4j-core", ":log4j-core:2.20.0")
            library("commons-lang", ":commons-lang:2.6")
            library("commons-lang3", ":commons-lang3:3.12.0")
            library("commons-lang3-old", ":commons-lang3:3.14.0")
            library("commons-configuration2", ":commons-configuration2:2.10.1")
            library("commons-collections4", ":commons-collections4:4.4")
            library("nimbus-jose-jwt", ":nimbus-jose-jwt:9.37.3")
            library("x509-common-util", ":x509-common-util:4.1.4")
            library("cryptotokens-api", ":cryptotokens-api:2.3.1")
            library("cryptotokens-impl", ":cryptotokens-impl:2.3.1")
            library("cryptotokens-impl-ee", ":cryptotokens-impl-ee:2.3.1")
            library("adsddl", ":adsddl:1.9")
            library("jakarta.jws-api", ":jakarta.jws-api:3.0.0")
            library("jakarta.xml.soap-api", ":jakarta.xml.soap-api:3.0.2")
            library("commons-logging", ":commons-logging:1.2")
            library("commons-codec", ":commons-codec:1.15")
            library("commons-io", ":commons-io:2.16.1")
            library("httpclient", ":httpclient:4.5.13")
            library("httpcore", ":httpcore:4.4.13")
            library("httpmime", ":httpmime:4.5.13")
            library("jldap", ":jldap:4.6.0")
            library("json-simple", ":json-simple:1.1.1")
            library("xmlpull", ":xmlpull:1.1.3.1")
            library("jakarta.xml.bind-api", ":jakarta.xml.bind-api:4.0.2")
            library("snakeyaml", ":snakeyaml:2.0")
            library("csrfguard", ":csrfguard:4.3.0-jakarta")
            library("csrfguard-extension-session", ":csrfguard-extension-session:4.3.0-jakarta")
            library("csrfguard-jsp-tags", ":csrfguard-jsp-tags:4.3.0-jakarta")
            library("primefaces", ":primefaces:14.0.0-jakarta")
            library("dnsjava", ":dnsjava:3.6.1")
            library("jackson-core", ":jackson-core:2.17.2")
            library("jackson-databind", ":jackson-databind:2.17.2")
            library("jackson-annotations", ":jackson-annotations:2.17.2")
            library("jackson-dataformat-yaml", ":jackson-dataformat-yaml:2.17.2")
            library("reflections", ":reflections:0.9.11")
            library("swagger-annotations", ":swagger-annotations-jakarta:2.2.22")
            library("swagger-core", ":swagger-core-jakarta:2.2.22")
            library("swagger-jaxrs", ":swagger-jaxrs2-jakarta:2.2.22")
            library("swagger-models", ":swagger-models-jakarta:2.2.22")
            library("swagger-integration", ":swagger-integration-jakarta:2.2.22")
            library("classgraph", ":classgraph:4.8.174")
            library("commons-fileupload2", ":commons-fileupload2-jakarta:2.0.0-M1")
            library("commons-fileupload2-core", ":commons-fileupload2-core:2.0.0-M2")
            library("commons-fileupload", ":commons-fileupload:1.5")
            library("jacknji11", ":jacknji11:1.3.1")
            library("p11ng", ":p11ng:0.25.1")
            library("protobuf-java", ":protobuf-java:3.25.5")
            library("ctlog", ":ctlog:0.1.7")
            library("commons-beanutils", ":commons-beanutils:1.9.4")
            library("commons-text", ":commons-text:1.10.0")
            library("angus.activation", ":angus.activation:2.0.2")
            library("myfaces-api", ":myfaces-api:4.0.2")
            library("kerb4j-server-common", ":kerb4j-server-common:0.1.2")
            library("kerb-core", ":kerb-core:2.0.3")
            library("kerb-crypto", ":kerb-crypto:2.0.3")
            library("kerby-asn1", ":kerby-asn1:2.0.3")
            library("keyfactor-commons-cli",":keyfactor-commons-cli:2.0.0")
            library("jsch", ":jsch:0.2.11")
            library("xstream", ":xstream:1.4.20")
            library("xpp3_min", ":xpp3_min:1.1.4c")
            library("istack-commons-runtime", ":istack-commons-runtime:3.0.11")
            library("saaj-impl", ":saaj-impl:3.0.0")
            library("streambuffer", ":streambuffer:2.1.0")
            library("woodstox-core", ":woodstox-core:6.5.0")
            library("wsdl4j", ":wsdl4j:1.6.3")
            library("jcip-annotations", ":jcip-annotations:1.0-1")
            library("jna", ":jna:5.12.1")
            // hibernate
            library("antlr4-runtime", ":antlr4-runtime:4.13.0")
            library("byte-buddy", ":byte-buddy:1.14.15")
            library("classmate", ":classmate:1.5.1")
            library("fastInfoset", ":FastInfoset:1.2.15")
            library("hibernate-community-dialects",":hibernate-community-dialects:6.5.2.Final")
            library("hibernate-commons-annotations", ":hibernate-commons-annotations:6.0.6.Final")
            library("hibernate-core", ":hibernate-core:6.5.2.Final")
            library("hibernate-validator", ":hibernate-validator:8.0.1.Final")
            library("istack-commons-runtime-old", ":istack-commons-runtime:3.0.7")
            library("jakarta.activation-api", ":jakarta.activation-api:2.1.0")
            library("jandex", ":jandex:3.1.2")
            library("javassist", ":javassist:3.29.2-GA")
            library("jakarta.persistence-api", ":jakarta.persistence-api:3.1.0")
            library("jboss-transaction-api_v12_spec", ":jboss-transaction-api_1.2_spec:1.1.1.Final")
            library("parsson", ":parsson:1.1.7")
            library("stax-ex", ":stax-ex:1.8")
            library("txw2", ":txw2:2.3.1")
            library("yasson", ":yasson:3.0.4")
            library("slf4j.api", ":slf4j-api:2.0.16")
            // test dependencies
            library("junit", ":junit:4.13.2")
            library("easymock", ":easymock:5.2.0")
            library("objenesis", ":objenesis:3.3")
            library("hamcrest-core", ":hamcrest-core:1.3")
            library("system-rules", ":system-rules:1.19.0")
            library("reactive-streams", ":reactive-streams:1.0.3")
            library("resteasy-client", ":resteasy-client:6.2.9.Final")
            library("resteasy-client-api", ":resteasy-client-api:6.2.9.Final")
            library("resteasy-core", ":resteasy-core:6.2.9.Final")
            library("resteasy-core-spi", ":resteasy-core-spi:6.2.9.Final")
            library("resteasy-undertow", ":resteasy-undertow:6.2.9.Final")
            library("undertow-core", ":undertow-core:2.3.17.Final")
            library("undertow-servlet", ":undertow-servlet:2.3.17.Final")
            library("xnio-api", ":xnio-api:3.8.16.Final")
            library("xnio-nio", ":xnio-nio:3.8.16.Final")
            library("wildfly-common", ":wildfly-common:1.5.4.Final")
            library("jboss-threads", ":jboss-threads:2.3.3.Final")
            library("jakarta.servlet-api", ":jakarta.servlet-api:6.1.0")
            library("resteasy-jackson2-provider", ":resteasy-jackson2-provider:6.2.9.Final")
            library("resteasy-multipart-provider", ":resteasy-multipart-provider:6.2.9.Final")
            library("json-patch", ":json-patch:1.13")
            library("jakarta.ws.rs-api", ":jakarta.ws.rs-api:4.0.0")
            library("jackson-jakarta-rs-base", ":jackson-jakarta-rs-base:2.17.2")
            library("jackson-jakarta-rs-json-provider", ":jackson-jakarta-rs-json-provider:2.17.2")
            library("jackson-module-jaxb-annotations", ":jackson-module-jaxb-annotations:2.17.2")
            library("jboss-logging", ":jboss-logging:3.6.0.Final")
            library("el-impl", ":el-impl:2.2")
            // bundles
            bundle(
                "test",
                listOf(
                    // junit
                    "junit",
                    "hamcrest-core",
                    "httpcore",
                    "httpclient",
                    "httpmime",
                    "commons-collections4",
                    "commons-configuration2",
                    "commons-text",
                    "commons-beanutils",
                    // easymock
                    "easymock",
                    "objenesis"
                )
            )
            bundle(
                "resteasy-jaxrs",
                listOf(
                    "reactive-streams",
                    "resteasy-client",
                    "resteasy-client-api",
                    "resteasy-core",
                    "resteasy-core-spi",
                    "resteasy-undertow",
                    "undertow-core",
                    "undertow-servlet",
                    "xnio-api",
                    "xnio-nio",
                    "wildfly-common",
                    "jboss-threads",
                    "jakarta-servlet-api",
                    "resteasy-jackson2-provider",
                    "resteasy-multipart-provider",
                    "json-patch",
                    "jakarta.ws.rs-api",
                    "jackson-jakarta-rs-base",
                    "jackson-jakarta-rs-json-provider",
                    "jackson-module-jaxb-annotations"
                )
            )
            bundle(
                "utils",
                listOf(
                    "commons-lang",
                    "commons-lang3",
                    "commons-configuration2",
                    "commons-collections4",
                    "commons-logging",
                    "commons-codec",
                    "commons-io",
                    "commons-fileupload",
                    "commons-beanutils",
                    "commons-text",
                    "log4j-api",
                    "log4j-core",
                    "log4j-v12-api"
                )
            )
            bundle(
                "jackson",
                listOf(
                    "jackson-core",
                    "jackson-databind",
                    "jackson-annotations",
                    "jackson-dataformat-yaml"
                )
            )
            bundle("bouncy.castle", listOf("bcprov", "bcpkix", "bctls", "bcutil"))
            bundle("xstream", listOf("xstream", "xmlpull", "xpp3_min"))
            bundle("xmlpull", listOf("xmlpull", "xpp3_min"))
            bundle("log4j", listOf("log4j-api", "log4j-core", "log4j-v12-api"))
            bundle("jacknji", listOf("jacknji11", "jna"))
            bundle("hibernate-validator", listOf("hibernate.validator", "el-impl"))

            val cryptoTokensLibraries = mutableListOf("cryptotokens-api", "cryptotokens-impl")
            if (edition == "ee") {
                cryptoTokensLibraries.add("cryptotokens-impl-ee")
            }
            bundle("cryptotokens", cryptoTokensLibraries)
        }
    }
}

if (edition == "ee") {
    include(
        "modules:acme:common",
        "modules:acme",
        "modules:edition-specific-ee",
        "modules:ejbca-entity:cli",
        "modules:statedump:common",
        "modules:peerconnector:common",
        "modules:peerconnector:interface",
        "modules:peerconnector:publ",
        "modules:peerconnector:ra",
        "modules:peerconnector:ejb",
        "modules:peerconnector:war",
        "modules:peerconnector:rar",
        "modules:peerconnector:cli",
        "modules:plugins-ee",
        "modules:statedump:cli",
        "modules:statedump:ejb",
        "modules:caa",
        "modules:caa:cli",
        "modules:cits:common",
        "modules:cits",
        "modules:configdump:common",
        "modules:configdump:cli",
        "modules:configdump:ejb",
        "modules:proxy-ca",
        "modules:ssh:common",
        "modules:ssh:war",
        "modules:msae",
        "modules:ejbca-rest-coap",
        "modules:ejbca-rest-configdump",
        "modules:ejbca-rest-cryptotoken",
        "modules:ejbca-rest-camanagement",
        "modules:ejbca-rest-endentity",
        "modules:ejbca-rest-ssh",
        "modules:p11ng-cli",
        "modules:est",
        "modules:ct",
        "modules:cesecore-cvcca",
        "modules:unidfnr",
    )
}

if (edition == "ce") {
    include(
        "modules:edition-specific:ejb", // In CE this module is used instead of edition-specific-ee
    )
}

include(
    "modules:cesecore-common",
    "modules:cesecore-entity",
    "modules:cesecore-ejb-interface",
    "modules:cesecore-x509ca",
    "modules:cesecore-ejb",
    "modules:ejbca-common",
    "modules:ejbca-entity",
    "modules:ejbca-ws:common",
    "modules:ejbca-ejb-interface",
    "modules:ejbca-common-web",
    "modules:ejbca-scep-war",
    "modules:ejbca-webdist-war",
    "modules:ejbca-cmp-war",
    "modules:healthcheck-war",
    "modules:clearcache-war",
    "modules:ejbca-properties",
    "modules:ejbca-rest-api",
    "modules:ejbca-rest-ca",
    "modules:ejbca-rest-certificate",
    "modules:ejbca-rest-system",
    "modules:ejbca-ws-cli",
    "modules:edition-specific:interface",
    "modules:plugins",
    "modules:ejbca-ejb",
    "modules:ejbca-ejb-cli",
    "modules:admin-gui",
    "modules:ra-gui",
    "modules:ejbca-ws",
    "modules:ejbca-rest-common",
    "modules:va",
    "modules:va:extensions",
    "modules:certificatestore",
    "modules:crlstore",
    "modules:systemtests:interface",
    "modules:systemtests:common",
    "modules:systemtests:ejb",
)
