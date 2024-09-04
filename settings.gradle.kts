rootProject.name = "ejbca"
val editionProp = providers.gradleProperty("edition").getOrElse("ee")
val eeModuleExists = file("modules/edition-specific-ee").exists()
val edition = if (editionProp == "ce" || !eeModuleExists) "ce" else "ee"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            library("bcprov", ":bcprov:jdk18on-1.78")
            library("bcpkix", ":bcpkix:jdk18on-1.78")
            library("bctls", ":bctls:jdk18on-1.78")
            library("bcutil", ":bcutil:jdk18on-1.78")
            library("ejbca-ws-client-gen", ":ejbca-ws-client-gen:1")
            library("caffeine", ":caffeine:3.1.6")
            library("jakartaee-api", ":jakarta.jakartaee-api:10.0.0")
            library("jakarta.xml.ws-api", ":jakarta.xml.ws-api:4.0.1")
            library("jaxb-runtime", ":jaxb-runtime:4.0.5")
            library("cert-cvc", ":cert-cvc:1.6.0")
            library("guava", ":guava:33.0.0-jre")
            library("log4j-v12-api", ":log4j-1.2-api:2.20.0")
            library("commons-lang", ":commons-lang:2.6")
            library("commons-lang3", ":commons-lang3:3.12.0")
            library("commons-lang3-old", ":commons-lang3:3.14.0")
            library("commons-configuration2", ":commons-configuration2:2.10.1")
            library("commons-collections4", ":commons-collections4:4.4")
            library("nimbus-jose-jwt", ":nimbus-jose-jwt:9.37.3")
            library("x509-common-util", ":x509-common-util:4.0.0")
            library("cryptotokens-api", ":cryptotokens-api:2.2.0")
            library("cryptotokens-impl", ":cryptotokens-impl:2.2.0")
            library("cryptotokens-impl-ee", ":cryptotokens-impl-ee:2.2.0")
            library("adsddl", ":adsddl:1.9")
            library("jakarta.jws-api", ":jakarta.jws-api:3.0.0")
            library("jakarta.xml.soap-api", ":jakarta.xml.soap-api:3.0.2")
            library("log4j-api", ":log4j-api:2.20.0")
            library("log4j-core", ":log4j-core:2.20.0")
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
            library("jackson-dataformat-yaml", ":jackson-dataformat-yaml:2.17.2")
            library("reflections", ":reflections:0.9.11")
            library("swagger-annotations", ":swagger-annotations-jakarta:2.2.22")
            library("swagger-core", ":swagger-core-jakarta:2.2.22")
            library("swagger-jaxrs", ":swagger-jaxrs2-jakarta:2.2.22")
            library("swagger-models", ":swagger-models-jakarta:2.2.22")
            library("swagger-integration", ":swagger-integration-jakarta:2.2.22")
            library("classgraph", ":classgraph:4.8.174")
            library("jackson-annotations", ":jackson-annotations:2.17.2")
            library("commons-fileupload2", ":commons-fileupload2-jakarta:2.0.0-M1")
            library("commons-fileupload2-core", ":commons-fileupload2-core:2.0.0-M2")
            library("commons-fileupload", ":commons-fileupload:1.5")
            library("jacknji11", ":jacknji11:1.3.1")
            library("p11ng", ":p11ng:0.24.0")
            library("protobuf-java", ":protobuf-java:3.25.3")
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
            library("junit", ":junit:4.13.2")
            library("istack-commons-runtime", ":istack-commons-runtime:3.0.11")
            library("saaj-impl", ":saaj-impl:3.0.0")
            library("streambuffer", ":streambuffer:2.1.0")
            library("woodstox-core", ":woodstox-core:6.5.0")
            library("wsdl4j", ":wsdl4j:1.6.3")
            library("jcip-annotations", ":jcip-annotations:1.0-1")
            library("jna", ":jna:5.12.1")
            library("javassist", ":javassist:3.29.2-GA")
            // hibernate
            library("antlr", ":antlr:2.7.7")
            library("byte-buddy", ":byte-buddy:1.10.17")
            library("classmate", ":classmate:1.5.1")
            library("dom4j", ":dom4j:2.1.3")
            library("fastInfoset", ":FastInfoset:1.2.15")
            library("hibernate-community-dialects",":hibernate-community-dialects:6.5.2.Final")
            library("hibernate-commons-annotations", ":hibernate-commons-annotations:5.1.2.Final")
            library("hibernate-core", ":hibernate-core:6.5.2.Final")
            library("hibernate-validator", ":hibernate-validator:8.0.1.Final")
            library("istack-commons-runtime-old", ":istack-commons-runtime:3.0.7")
            library("jakarta.activation-api", ":jakarta.activation-api:2.1.0")
            library("jandex", ":jandex:2.1.3.Final")
            library("jakarta.persistence-api", ":jakarta.persistence-api:3.1.0")
            library("jboss-transaction-api_v12_spec", ":jboss-transaction-api_1.2_spec:1.1.1.Final")
            library("stax-ex", ":stax-ex:1.8")
            library("txw2", ":txw2:2.3.1")
            // test
            library("junit", ":junit:4.13.2")
            library("easymock",":easymock:5.2.0")
            library("hamcrest",":hamcrest-core:1.3")
            library("javassist",":javassist:3.29.2-GA")
            library("objenesis",":objenesis:3.3")
            library("slf4j-api",":slf4j-api:2.0.16")
            library("slf4j-reload4j",":slf4j-reload4j:2.0.16")
        }
    }
}

if (edition == "ee") {
    include(
        "modules:acme:common",
        "modules:acme",
        "modules:edition-specific-ee",
        "modules:statedump:common",
        "modules:peerconnector:common",
        "modules:peerconnector:interface",
        "modules:peerconnector:publ",
        "modules:peerconnector:ra",
        "modules:peerconnector:ejb",
        "modules:peerconnector:war",
        "modules:peerconnector:rar",
        "modules:plugins-ee",
        "modules:statedump:ejb",
        "modules:cits:common",
        "modules:cits",
        "modules:configdump:common",
        "modules:configdump:ejb",
        "modules:proxy-ca",
        "modules:ssh:common",
        "modules:ssh:war",
        "modules:msae",
        "modules:ejbca-rest-certificate",
        "modules:ejbca-rest-coap",
        "modules:ejbca-rest-configdump",
        "modules:ejbca-rest-ca",
        "modules:ejbca-rest-cryptotoken",
        "modules:ejbca-rest-camanagement",
        "modules:ejbca-rest-endentity",
        "modules:ejbca-rest-ssh",
        "modules:ejbca-rest-system",
        "modules:ejbca-rest-api",
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
    "modules:ejbca-ws-cli",
    "modules:edition-specific:interface",
    "modules:plugins",
    "modules:caa",
    "modules:ejbca-ejb",
    "modules:admin-gui",
    "modules:ra-gui",
    "modules:ejbca-ws",
    "modules:ejbca-rest-common",
    "modules:ct",
    "modules:va",
    "modules:va:extensions",
    "modules:certificatestore",
    "modules:crlstore",
    "modules:est",
    "modules:unidfnr",
    "modules:cesecore-cvcca",
    "modules:systemtests:interface",
    "modules:systemtests:common",
    "modules:systemtests:ejb",
)
