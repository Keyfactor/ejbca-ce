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
package org.ejbca.ui.web.rest.api.resource;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

public class CaRestResourceFalconSystemTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(CaRestResourceFalconSystemTest.class);
    
    private static final String TEST_ISSUER_FALCON_512 = "CN=CaRestResourceSystemTestFalcon-" + new Random().nextInt();
    private static String CRL_FILENAME = "CaRestResourceSystemTestCrlFile-" + new Random().nextInt();
    
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    @Rule
    public final TestWatcher traceLogMethodsRule = new TraceLogMethodsTestWatcher(log);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }
    
    @Before
    public void setUp() throws Exception {
        final X509CA ca = CaTestUtils.createTestX509CA(
                TEST_ISSUER_FALCON_512, 
                "foo123".toCharArray(), 
                false, 
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign,
                AlgorithmConstants.SIGALG_FALCON512);
        
        final X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();
        cainfo.setCrlPartitions(5);
        cainfo.setUsePartitionedCrl(true);
        cainfo.setDeltaCRLPeriod(100_000);
        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint("http://localhost:8080/ejbca/publicweb/webdist/certdist" + "?cmd=crl&issuer=CN%3D" + TEST_ISSUER_FALCON_512 + "&partition=*");
        caAdminSession.createCA(INTERNAL_ADMIN_TOKEN, cainfo);
    }

    @After
    public void tearDown() throws Exception {        
        CaRestResourceSystemTest.removeCa((X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_FALCON_512.hashCode()));
        Files.deleteIfExists(Paths.get(CRL_FILENAME));
    }
    
    @Test
    public void testCreateCrlWithoutDeltaCrlFalcon512() throws Exception {
        // without delta
        String responseBody = CaRestResourceSystemTest.createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_FALCON_512) + "/createcrl?deltacrl=false");

        CaRestResourceSystemTest.assertTrue(responseBody, ("\"all_success\":true"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":2,"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":3,"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_crl_version\":3"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_delta_crl_version\":2"));

        // with delta
        responseBody = CaRestResourceSystemTest.createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_FALCON_512) + "/createcrl?deltacrl=true");
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"all_success\":true"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":4,"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":3,"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_crl_version\":3"));
        CaRestResourceSystemTest.assertTrue(responseBody, ("\"latest_delta_crl_version\":4"));
    }
    
}
