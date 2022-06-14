/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;

import java.net.URLEncoder;
import java.util.Random;

import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * A set of system tests for CaRestResource ('').
 */
public class CaRestResourceSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CaRestResourceSystemTest.class);
        
    private static String TEST_ISSUER_DN1 = "CN=CaRestResourceSystemTest1";
    private static String TEST_ISSUER_DN2 = "CN=CaRestResourceSystemTest2";
    private static String TEST_ISSUER_DN_NO_PARTITION = "CN=CaRestResourceSystemTestNoPartition";
        
    private static final CAAdminSessionRemote caAdminSession = 
                            EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
        Random random = new Random();
        TEST_ISSUER_DN1 += random.nextInt();
        TEST_ISSUER_DN2 += random.nextInt();
        TEST_ISSUER_DN_NO_PARTITION += random.nextInt();
        
        CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN1);
        CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2);
        CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN_NO_PARTITION);
        
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN1.hashCode());
        cainfo.setCrlPartitions(5);
        cainfo.setUsePartitionedCrl(true);
        cainfo.setDeltaCRLPeriod(0);
        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint("http://localhost:8080/ejbca/publicweb/webdist/certdist"
                + "?cmd=crl&issuer=CN%3DCaRestResourceSystemTest1&partition=*");
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, cainfo);
        
        cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2.hashCode());
        cainfo.setCrlPartitions(5);
        cainfo.setUsePartitionedCrl(true);
        cainfo.setDeltaCRLPeriod(100_000);
        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint("http://localhost:8080/ejbca/publicweb/webdist/certdist"
                + "?cmd=crl&issuer=CN%3DCaRestResourceSystemTest2&partition=*");
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, cainfo);
        
        Thread.sleep(10000);
        
    }

    private static void removeCa(X509CAInfo cainfo) {
        try {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, cainfo);
        } catch (Exception e) {
            //continue to next
        }
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN1.hashCode());
        removeCa(cainfo);
        
        cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2.hashCode());
        removeCa(cainfo);
        
        cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN_NO_PARTITION.hashCode());
        removeCa(cainfo);
        
        RestResourceSystemTestBase.afterClass();
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }
    
    private void assertTrue(String responseBody, String content) {
       Assert.assertTrue("does not contain: " + content, responseBody.contains(content));  
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final Response actualResponse = newRequest("/v1/ca/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        // then
        assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }    

    /**
     * Disables REST and then runs a simple REST access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws Exception 
     */
    @Test
    public void shouldRestrictAccessToRestResourceIfProtocolDisabled() throws Exception {
        // given
        disableRestProtocolConfiguration();
        // when
        final Response actualResponse = newRequest("/v1/ca/status").request().get();
        final int status = actualResponse.getStatus();
        // then
        assertEquals("Unexpected response after disabling protocol", 403, status);
        // restore state
        enableRestProtocolConfiguration();
    }
    
    private String createCrl(String url) throws Exception {
        WebTarget request = newRequest(url);
        Response actualResponse = request.request().post(null);
        String responseBody = actualResponse.readEntity(String.class);
        log.error("responseBody: " + responseBody);
        actualResponse.close();
        assertEquals(actualResponse.getStatus(), 200);
        return responseBody;
    }
    
    @Test
    public void testCreateCrlWithoutDeltaCrl() throws Exception {
        log.error("testCreateCrlWithoutDeltaCrl");
        // with delta
        String responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN1, "UTF-8") + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":false"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));
        
        // without delta
        responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN1, "UTF-8") + "/createcrl??deltacrl=false");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":2,"));
        assertTrue(responseBody, ("\"latest_crl_version\":2"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));
        
    }
    
    @Test
    public void testCreateCrlWithDeltaCrl() throws Exception {
        log.error("testCreateCrlWithDeltaCrl");
        // without delta
        String responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN2, "UTF-8") + "/createcrl");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));
        
        // with delta
        responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN2, "UTF-8") + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":3,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":2,"));
        assertTrue(responseBody, ("\"latest_crl_version\":2"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":3"));
        
        // suspend two partition
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2.hashCode());
        cainfo.setSuspendedCrlPartitions(2);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, cainfo);
        
        // with delta
        responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN2, "UTF-8") + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":5,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":4,"));
        assertTrue(responseBody, ("\"latest_crl_version\":4"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":5"));
    }
    
    @Test
    public void testCreateCrlNoPartition() throws Exception {
        log.error("testCreateCrlNoPartition");
        
        // with delta
        String responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN_NO_PARTITION, "UTF-8") + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2")); // generated over base version
        
        // without delta
        responseBody = createCrl("/v1/ca/" + URLEncoder.encode(TEST_ISSUER_DN_NO_PARTITION, "UTF-8") + "/createcrl?deltacrl=false");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":3"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2")); // did not generate
    }
    
    @Test
    public void testCreateCrlInvalidIssuer() throws Exception {
        log.error("testCreateCrlInvalidIssuer");
        
        WebTarget request = newRequest("/v1/ca/" + URLEncoder.encode("CN=InvalidCa", "UTF-8") + "/createcrl?deltacrl=false");
        Response actualResponse = request.request().post(null);
        String responseBody = actualResponse.readEntity(String.class);
        log.error("responseBody: " + responseBody);
        actualResponse.close();
        assertEquals(actualResponse.getStatus(), 400);
        
    }
    
}
