rootProject.name = "ejbca"
val editionProp = providers.gradleProperty("edition").getOrElse("ee")
val eeModuleExists = file("modules/edition-specific-ee").exists()
val edition = if (editionProp == "ce" || !eeModuleExists) "ce" else "ee"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            library("bcprov", ":bcprov:jdk18on-175")
            library("bcpkix", ":bcpkix:jdk18on-175")
            library("bctls", ":bctls:jdk18on-175")
            library("bcutil", ":bcutil:jdk18on-175")
            library("ejbca-ws-client-gen", ":ejbca-ws-client-gen:1")
            library("caffeine", ":caffeine:3.1.6")
            library("java-ee-api", ":javaee-api:8.0.1")
            library("jaxws-api", ":jaxws-api:2.3.1")
            library("jaxb-runtime", ":jaxb-runtime:2.3.1")
            library("cert-cvc", ":cert-cvc:1.5.0")
            library("guava", ":guava:33.0.0-jre")
            library("log4j-v12-api", ":log4j-1.2-api:2.20.0")
            library("commons-lang", ":commons-lang:2.6")
            library("commons-lang3", ":commons-lang3:3.12.0")
            library("commons-lang3-old", ":commons-lang3:3.2.1")
            library("commons-configuration2", ":commons-configuration2:2.8.0")
            library("commons-collections4", ":commons-collections4:4.4")
            library("nimbus-jose-jwt", ":nimbus-jose-jwt:9.24.4")
            library("x509-common-util", ":x509-common-util:2.2.0")
            library("cryptotokens-impl", ":cryptotokens-impl:0.0.5")
            library("adsddl", ":adsddl:1.9")
            library("javax.jws-api", ":javax.jws-api:1.1")
            library("javax.xml.soap-api", ":javax.xml.soap-api:1.4.0")
            library("log4j-api", ":log4j-api:2.20.0")
            library("log4j-core", ":log4j-core:2.20.0")
            library("commons-logging", ":commons-logging:1.2")
            library("commons-codec", ":commons-codec:1.15")
            library("commons-io", ":commons-io:2.11.0")
            library("httpclient", ":httpclient:4.5.13")
            library("httpcore", ":httpcore:4.4.13")
            library("httpmime", ":httpmime:4.5.13")
            library("jldap", ":jldap:4.6.0")
            library("json-simple", ":json-simple:1.1.1")
            library("xmlpull", ":xmlpull:1.1.3.1")
            library("jakarta.xml.bind-api", ":jakarta.xml.bind-api:2.3.3")
            library("snakeyaml", ":snakeyaml:2.0")
            library("csrfguard", ":csrfguard:4.3.0")
            library("csrfguard-extension-session", ":csrfguard-extension-session:4.3.0")
            library("csrfguard-jsp-tags", ":csrfguard-jsp-tags:4.3.0")
            library("primefaces", ":primefaces:12.0.0")
            library("dnsjava", ":dnsjava:3.5.2")
            library("jackson-core", ":jackson-core:2.14.2")
            library("jackson-databind", ":jackson-databind:2.14.2")
            library("jackson-dataformat-yaml", ":jackson-dataformat-yaml:2.14.2")
            library("reflections", ":reflections:0.9.11")
            library("swagger-annotations", ":swagger-annotations:1.6.4")
            library("swagger-core", ":swagger-core:1.6.4")
            library("swagger-jaxrs", ":swagger-jaxrs:1.6.4")
            library("swagger-models", ":swagger-models:1.6.4")
            library("jackson-annotations", ":jackson-annotations:2.14.2")
            library("jacknji11", ":jacknji11:1.2.10")
            library("p11ng", ":p11ng:0.22.0")
            library("commons-fileupload", ":commons-fileupload:1.5")
            library("protobuf-java", ":protobuf-java:3.5.1")
            library("ctlog", ":ctlog:0.1.6")
            library("commons-beanutils", ":commons-beanutils:1.9.4")
            library("commons-text", ":commons-text:1.10.0")
            library("activation", ":activation:1.1.1")
            library("myfaces-api", ":myfaces-api:2.3.9")
            library("kerb4j-server-common", ":kerb4j-server-common:0.1.2")
            library("kerb-core", ":kerb-core:2.0.3")
            library("kerb-crypto", ":kerb-crypto:2.0.3")
            library("kerby-asn1", ":kerby-asn1:2.0.3")
            library("jsch", ":jsch:0.2.11")
            library("xstream", ":xstream:1.4.20")
            library("xpp3_min", ":xpp3_min:1.1.4c")
            library("junit", ":junit:4.13.2")
            library("istack-commons-runtime", ":istack-commons-runtime:3.0.11")
            library("saaj-impl", ":saaj-impl:1.5.3")
            library("streambuffer", ":streambuffer:1.5.10")
            library("woodstox-core", ":woodstox-core:6.4.0")
            library("wsdl4j", ":wsdl4j:1.6.3")
            library("jcip-annotations", ":jcip-annotations:1.0-1")
            library("jna", ":jna:5.12.1")
            // hibernate
            library("antlr", ":antlr:2.7.7")
            library("byte-buddy", ":byte-buddy:1.10.17")
            library("classmate", ":classmate:1.5.1")
            library("dom4j", ":dom4j:2.1.3")
            library("fastInfoset", ":FastInfoset:1.2.15")
            library("hibernate-commons-annotations", ":hibernate-commons-annotations:5.1.2.Final")
            library("hibernate-core", ":hibernate-core:5.4.25.Final")
            library("hibernate-validator", ":hibernate-validator:6.2.5.Final")
            library("istack-commons-runtime-old", ":istack-commons-runtime:3.0.7")
            library("jakarta.activation-api", ":jakarta.activation-api:2.1.0")
            library("jandex", ":jandex:2.1.3.Final")
            library("javax.persistence-api", ":javax.persistence-api:2.2")
            library("jaxb-api", ":jaxb-api:2.3.1")
            library("jboss-transaction-api_v12_spec", ":jboss-transaction-api_1.2_spec:1.1.1.Final")
            library("stax-ex", ":stax-ex:1.8")
            library("txw2", ":txw2:2.3.1")
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
