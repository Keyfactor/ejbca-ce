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
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509CRL;
import java.util.Map;
import java.util.Random;

import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
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

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * A set of system tests for CaRestResource ('').
 */
public class CaRestResourceSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CaRestResourceSystemTest.class);
        
    private static String TEST_ISSUER_DN1 = "CN=CaRestResourceSystemTest1";
    private static String TEST_ISSUER_DN2 = "CN=CaRestResourceSystemTest2";
    private static String TEST_ISSUER_DN_NO_PARTITION = "CN=CaRestResourceSystemTestNoPartition";
    private static String CRL_FILENAME = "CaRestResourceSystemTestCrlFile";


    private static final CAAdminSessionRemote caAdminSession = 
                            EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
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
        RestResourceSystemTestBase.afterClass();
    }

    @Before
    public void setUp() throws Exception{
        Random random = new Random();
        TEST_ISSUER_DN1 += random.nextInt();
        TEST_ISSUER_DN2 += random.nextInt();
        TEST_ISSUER_DN_NO_PARTITION += random.nextInt();
        CRL_FILENAME += random.nextInt();

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
    }

    @After
    public void tearDown() throws Exception {

        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN1.hashCode());
        removeCa(cainfo);
        
        cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2.hashCode());
        removeCa(cainfo);
        
        cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN_NO_PARTITION.hashCode());
        removeCa(cainfo);

        Files.deleteIfExists(Paths.get(CRL_FILENAME));
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
        assertEquals(200, actualResponse.getStatus());
        return responseBody;
    }
    
    @Test
    public void testCreateCrlWithoutDeltaCrl() throws Exception {
        log.error("testCreateCrlWithoutDeltaCrl");
        // with delta
        String responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":false"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));
        
        // without delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl??deltacrl=false");
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
        String responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));
        
        // with delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl?deltacrl=true");
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
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl?deltacrl=true");
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
        String responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN_NO_PARTITION) + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2")); // generated over base version
        
        // without delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN_NO_PARTITION) + "/createcrl?deltacrl=false");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":3"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2")); // did not generate
    }
    
    @Test
    public void testCreateCrlInvalidIssuer() throws Exception {
        log.error("testCreateCrlInvalidIssuer");
        
        WebTarget request = newRequest("/v1/ca/" + encodeUrl("CN=InvalidCa") + "/createcrl?deltacrl=false");
        Response actualResponse = request.request().post(null);
        String responseBody = actualResponse.readEntity(String.class);
        log.error("responseBody: " + responseBody);
        actualResponse.close();
        assertEquals(400, actualResponse.getStatus());
        
    }

    @Test
    public void crlImportShouldReturnBadRequestOnNonExistingCa() throws Exception {
        // given
        final String issuerDn = "CN=InvalidCa";
        // when
        final WebTarget request = newRequest(getImportCrlPath(issuerDn));
        final Response actualResponse = request.request().post(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        actualResponse.close();
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CA with DN: " + issuerDn + " does not exist.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnMissingFile() throws Exception {
        // when
        final WebTarget request = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response actualResponse = request.request().post(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        actualResponse.close();
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "No file uploaded.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnIncorrectFileFormFieldName() throws Exception {
        // given
        File fileToUpload = new File(CRL_FILENAME);
        fileToUpload.createNewFile();
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
        entityBuilder.addBinaryBody("invalidFormFieldName", fileToUpload, ContentType.DEFAULT_BINARY, CRL_FILENAME);
        HttpEntity entity = entityBuilder.build();
        // when
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        final String actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "No CRL file uploaded.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnInvalidPartitionIndex() throws Exception {
        // given
        String negativeCrlPartitionIndex = "-1";
        String nonNumericCrlPartitionIndex = "one";
        String decimalCrlPartitionIndex = "3.14";

        HttpEntity negativeCrlPartitionIndexEntity = MultipartEntityBuilder.create()
                .addPart("crlPartitionIndex", new StringBody(negativeCrlPartitionIndex, ContentType.MULTIPART_FORM_DATA))
                .build();
        HttpEntity nonNumericCrlPartitionIndexEntity = MultipartEntityBuilder.create()
                .addPart("crlPartitionIndex", new StringBody(nonNumericCrlPartitionIndex, ContentType.MULTIPART_FORM_DATA))
                .build();
        HttpEntity decimalCrlPartitionIndexEntity = MultipartEntityBuilder.create()
                .addPart("crlPartitionIndex", new StringBody(decimalCrlPartitionIndex, ContentType.MULTIPART_FORM_DATA))
                .build();

        // when negativeCrlPartitionIndex
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(negativeCrlPartitionIndexEntity);
        HttpResponse response = getHttpClient(true).execute(post);
        String actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: " + negativeCrlPartitionIndex + ", should be 0 or greater.", actualJsonString);

        // when nonNumericCrlPartitionIndex
        post.setEntity(nonNumericCrlPartitionIndexEntity);
        response = getHttpClient(true).execute(post);
        actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: " + nonNumericCrlPartitionIndex + ", should be 0 or greater.", actualJsonString);

        // when decimalCrlPartitionIndex
        post.setEntity(decimalCrlPartitionIndexEntity);
        response = getHttpClient(true).execute(post);
        actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: " + decimalCrlPartitionIndex + ", should be 0 or greater.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnInvalidFileContent() throws Exception {
        // given
        File fileToUpload = new File(CRL_FILENAME);
        fileToUpload.createNewFile(); // empty file
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
        entityBuilder.addBinaryBody("crlFile", fileToUpload, ContentType.DEFAULT_BINARY, CRL_FILENAME);
        HttpEntity entity = entityBuilder.build();
        // when
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        final String actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Could not parse CRL. It must be in DER format.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestWhenFileIsIssuedByAnotherCa() throws Exception {
        // given a CRL issued by CA "A"
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN2);
        final HttpEntity entity = prepareCrlImportEntity(x509Crl);
        // when uploading the CRL to CA "B"
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        final String actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CRL is not issued by " + TEST_ISSUER_DN1, actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestWhenUploadingAnOldCrl() throws Exception {
        // given
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl"); // CRL #1 - will attempt to upload again
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        final HttpEntity entity = prepareCrlImportEntity(x509Crl);
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl"); // CRL #2 - latest in DB
        // when
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        final String actualJsonString = EntityUtils.toString(response.getEntity());
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CRL #1 or higher is already in the database.", actualJsonString);
    }

    @Test
    public void crlImportShouldCreateANewCrl() throws Exception {
        // given
        // create a CRL, store it to a file for the import test and delete the existing one from DB
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        CaTestUtils.removeCrlByIssuerDn(TEST_ISSUER_DN1);
        assertNull(getLatestCrl(TEST_ISSUER_DN1));
        final HttpEntity entity = prepareCrlImportEntity(x509Crl);
        // when
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        // then
        assertEquals("CRL import failed", Status.OK.getStatusCode(), response.getStatusLine().getStatusCode());
        assertNotNull("New CRL was not returned by API /getLatestCrl", getLatestCrl(TEST_ISSUER_DN1));
    }

    @Test
    public void crlImportShouldCreateCrlInSpecificPartition() throws Exception {
        // given
        int crlPartitionIndex = 2;
        // create a CRL, store it to a file for the import test and delete the existing one from DB
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        CaTestUtils.removeCrlByIssuerDn(TEST_ISSUER_DN1);
        assertNull(getLatestCrl(TEST_ISSUER_DN1));
        final HttpEntity entity = prepareCrlImportEntity(x509Crl, crlPartitionIndex);
        // when
        final HttpPost post = new HttpPost(getBaseUrl() + getImportCrlPath(TEST_ISSUER_DN1));
        post.setEntity(entity);
        final HttpResponse response = getHttpClient(true).execute(post);
        // then
        assertEquals("CRL import failed", Status.OK.getStatusCode(), response.getStatusLine().getStatusCode());
        assertNotNull("New CRL was not returned by API /getLatestCrl", getLatestCrl(TEST_ISSUER_DN1, false, crlPartitionIndex));
    }

    /**
     * Prepares multipart form entity with parts for CRL file and crlPartitionIndex.
     * @param x509Crl Certificate revocation list
     * @param crlPartitionIndex CRL partition index
     * @return Multipart form entity
     */
    private HttpEntity prepareCrlImportEntity(X509CRL x509Crl, int crlPartitionIndex) throws Exception {
        Files.write(Paths.get(CRL_FILENAME), x509Crl.getEncoded());
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
        entityBuilder.addBinaryBody("crlFile", new File(CRL_FILENAME), ContentType.DEFAULT_BINARY, CRL_FILENAME);
        entityBuilder.addPart("crlPartitionIndex", new StringBody(String.valueOf(crlPartitionIndex), ContentType.MULTIPART_FORM_DATA));
        return entityBuilder.build();
    }

    /**
     * Prepares multipart form entity with parts for CRL file and crlPartitionIndex = 0.
     * @param x509Crl Certificate revocation list
     * @return Multipart form entity
     */
    private HttpEntity prepareCrlImportEntity(X509CRL x509Crl) throws Exception {
        return prepareCrlImportEntity(x509Crl, CertificateConstants.NO_CRL_PARTITION);
    }

    /**
     * Get the latest CRL via REST API /getLatestCrl
     * @param issuerDn Issuer DN
     * @param crlPartitionIndex CRL partition index number
     * @param deltaCrl false (full) or true (delta)
     * @return X509CRL certificate revocation list
     */
    private X509CRL getLatestCrl(String issuerDn, boolean deltaCrl, int crlPartitionIndex) throws Exception {
        final WebTarget latestCrlRequest = newRequest("/v1/ca/" + encodeUrl(issuerDn) +
                "/getLatestCrl?deltaCrl=" + deltaCrl + "&crlPartitionIndex=" + crlPartitionIndex);
        final Response latestCrlResponse = latestCrlRequest.request().get();
        final Object latestCrlDer = latestCrlResponse.readEntity(Map.class).get("crl");
        return latestCrlDer == null ? null : CertTools.getCRLfromByteArray(Base64.decode(latestCrlDer.toString().getBytes()));
    }

    /**
     * Get the latest full CRL for default partition 0
     * @param issuerDn Issuer DN
     * @return X509CRL certificate revocation list
     */
    private X509CRL getLatestCrl(String issuerDn) throws Exception {
        return getLatestCrl(issuerDn, false, CertificateConstants.NO_CRL_PARTITION);
    }

    private String getImportCrlPath(String issuerDn) {
        return "/v1/ca/" + encodeUrl(issuerDn) + "/importcrl";
    }
}
