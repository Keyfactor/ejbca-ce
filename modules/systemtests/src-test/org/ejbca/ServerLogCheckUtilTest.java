/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca;

import static org.junit.Assert.assertEquals;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.ejbca.ServerLogCheckUtil.ServerLogRecord;
import org.junit.BeforeClass;
import org.junit.Test;

public class ServerLogCheckUtilTest {
    
    private static final Logger log = Logger.getLogger(ServerLogCheckUtilTest.class);
    private static final String LOG_SNIPPET = 
              "[0m[0m08:36:12,174 INFO  [org.jboss.as.ejb3] (MSC service thread 1-5) WFLYEJB0493: Jakarta Enterprise Beans subsystem suspension complete\n"
            + "[0m[0m08:36:12,211 INFO  [org.jboss.as.patching] (MSC service thread 1-1) WFLYPAT0050: WildFly Full cumulative patch ID is: base, one-off patches include: none\n"
            + "[0m[0m08:39:13,947 ERROR  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:14,070 WARN  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [322] Error retrieving CRL for issuer 'CN=CaRestResourceSystemTest11619651981-440507607' with CRL number 0.\n"
            + "[0m[0m08:39:14,137 DEBUG  [org.ejbca.core.ejb.crl.ImportCrlSessionBean] (default task-2) [verifyCrlIssuer] [173] CA: CN=CaRestResourceSystemTest11619651981-440507607\n"
            + "[0m[0m08:39:14,141 INFO  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [322] Error retrieving CRL for issuer 'CN=CaRestResourceSystemTest11619651981-440507607' with CRL number 0. CRL partition: 2\n"
            + "";
    
    private static final String SAMPLE_WHITELIST_CONFIG = "{\n"
            + "  \"packages\": [\"org.cesecore.certificates.ca\", \"org.cesecore.keybind\"],\n"
            + "  \"classes\": [\"CertificateProfileSessionBean\", \"CAAdminSessionBean\", \"CrlStoreSessionBean\"],\n"
            + "  \"methods\": [\n"
            + "    {\n"
            + "      \"class\": \"CertificateCreateSessionBean\",\n"
            + "      \"ignoredMethods\": [\"createItsCertificate\"]\n"
            + "    },\n"
            + "    {\n"
            + "      \"class\": \"RestLoggingFilter\",\n"
            + "      \"ignoredMethods\": [\"doFilter\"],\n"
            + "      \"prefixes\": [\"ca/\"]\n"
            + "    }\n"
            + "  ]\n"
            + "}\n"
            + "";
    
    private static final String LOG_SNIPPET_WHITELIST = 
            "[0m[0m08:39:13,947 INFO  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.cesecore.certificates.dummy.CAAdminSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.cesecore.certificates.dummy.CertificateCreateSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.cesecore.certificates.dummy.CertificateCreateSessionBean] (default task-2) [createItsCertificate] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.cesecore.certificates.dummy.CertificateCreateSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m07:07:00,224 INFO  [org.ejbca.ui.web.rest.api.config.RestLoggingFilter] (default task-1) [doFilter] [152] PUT https://localhost:8443/ejbca/ejbca-rest-api/v1/certificate/C=SE,CN=CertificateRestSystemTestCa-34960277/3A4C385638892A21E0EBC29CF57E83E7022030AA/revoke/ received from 127.0.0.1  X-Forwarded-For: null\n"
            + "[0m[0m07:06:38,366 INFO  [org.ejbca.ui.web.rest.api.config.RestLoggingFilter] (default task-2) [doFilter] [152] GET https://localhost:8443/ejbca/ejbca-rest-api/v1/ca/CN=CertificateRestSystemTestCa-1054553211,C=SE/getLatestCrl received from 127.0.0.1  X-Forwarded-For: null\n"
            + "[0m[0m07:09:26,037 INFO  [org.ejbca.ui.web.rest.api.resource.EndEntityRestResource] (default task-2) [setstatus] [173] End entity 'EndEntityRestResourceSystemTest2m3nQUcB' successfully edited by administrator CN=RestApiTestUser\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.SomeImaginaryBean] (default task-2) [isAuthorizedForSomething] [312] Checking 'CN=SomeCaDn7890' for something.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] Dreams of issuer 'CN=HopefulIssuer', is not present.\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] Creating CertificateData, subjectDN=<redacted>, subjectAltName=<redacted>, issuer=, fingerprint=bb1dab93e596d7dcc9953cbd2fbe794f00fd3198, storeSubjectAltName=true\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] Merging crypto token to database: CaTestUtils.createTestX509CA.CN=CaRestResourceSystemTest21533841461\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] Some base64 logging MIIasdaklkjkaw81783nandkqw=\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] user CN=EverythingIncludedIsNonMatter\n"
            + "[0m[0m08:39:13,947 DEBUG  [org.ejbca.dummy.AnotherImaginaryBean] (default task-2) [getDreams] [421] issuer Dn(transformed) 'CN=EverythingIncludedIsNonMatter'\n";
    
    
    @BeforeClass
    public static void init() {
        new ServerLogCheckUtil().loadWhiteListPiiConfiguration(SAMPLE_WHITELIST_CONFIG);
        log.error(ServerLogCheckUtil.whiteListedPackages);
        log.error(ServerLogCheckUtil.whiteListedClasses);
        log.error(ServerLogCheckUtil.whiteListedMethods);
        log.error(ServerLogCheckUtil.whiteListedConditionalMethods);
    }
    
    @Test
    public void testReadLine() {
        boolean[] expectedNull = {true, true, false, false, false, false, true};
        String[] logLines = LOG_SNIPPET.split("\n");
        for (int i=0; i<7; i++) {
            ServerLogRecord logRecord = ServerLogCheckUtil.parseServerLogRecord(logLines[i]);
            assertEquals("logRecord is processed incorrectly", logRecord==null, expectedNull[i]);
        }
    }
    
    @Test
    public void testWhitelist() {
        boolean[] expectedWhiteListed = {true, true, false, true, true, false, true, true, true, true, true, true, false, true, true};
        String[] logLines = LOG_SNIPPET_WHITELIST.split("\n");
        Set<String> issuerDns = new HashSet<>();
        issuerDns.add("CN=HopefulIssuer");
        issuerDns.add("CN=CaRestResourceSystemTest21533841461");
        Set<String> adminDns = new HashSet<>();
        adminDns.add("CN=SomeCaDn7890");
        for (int i=0; i<expectedWhiteListed.length; i++) {
            ServerLogRecord logRecord = ServerLogCheckUtil.parseServerLogRecord(logLines[i]);
            assertEquals("logRecord is whitelisted incorrectly: " + logRecord, 
                    logRecord.isWhiteListed(issuerDns, adminDns), expectedWhiteListed[i]);
        }
    }

}
