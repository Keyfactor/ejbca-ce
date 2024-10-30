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

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.EntityPart;
import jakarta.ws.rs.core.GenericEntity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

/**
 * A set of system tests for CaRestResource ('').
 */
public class CaRestResourceSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CaRestResourceSystemTest.class);
        
    private static String TEST_ISSUER_DN1 = "CN=CaRestResourceSystemTest1";
    private static String TEST_ISSUER_DN2 = "CN=CaRestResourceSystemTest2";
    private static String TEST_ISSUER_DN_NO_PARTITION = "CN=CaRestResourceSystemTestNoPartition";
    private static String CRL_FILENAME = "CaRestResourceSystemTestCrlFile";

    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    public static void removeCa(X509CAInfo cainfo) {
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
        cainfo.setDeltaCRLPeriod(100_000); // Is required to be able to create delta crls
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

    public static void assertTrue(String responseBody, String content) {
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
    
    public static String createCrl(String url) throws Exception {
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
        // without delta
        String responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl?deltacrl=false");

        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":0,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0"));

        // with delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":2,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2"));
    }

    @Test
    public void testCreateCrlWithDeltaCrl() throws Exception {
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
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":2,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2"));

        // suspend two partition
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfo(INTERNAL_ADMIN_TOKEN, TEST_ISSUER_DN2.hashCode());
        cainfo.setSuspendedCrlPartitions(2);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, cainfo);

        // with delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":{\"partition_5\":3,"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":{\"partition_5\":1,"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":3"));
    }

    @Test
    public void testCreateCrlNoPartition() throws Exception {
        // first we generate base CRL without delta
        String responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN_NO_PARTITION) + "/createcrl?deltacrl=false");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":0")); // did not generate


        // with delta
        responseBody = createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN_NO_PARTITION) + "/createcrl?deltacrl=true");
        assertTrue(responseBody, ("\"all_success\":true"));
        assertTrue(responseBody, ("\"latest_partition_delta_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_partition_crl_versions\":null"));
        assertTrue(responseBody, ("\"latest_crl_version\":1"));
        assertTrue(responseBody, ("\"latest_delta_crl_version\":2")); // generated over base version
    }

    @Test
    public void testCreateCrlInvalidIssuer() throws Exception {
        WebTarget request = newRequest("/v1/ca/" + encodeUrl("CN=InvalidCa") + "/createcrl?deltacrl=false");
        Response actualResponse = request.request().post(null);
        String responseBody = actualResponse.readEntity(String.class);
        log.error("responseBody: " + responseBody);
        actualResponse.close();
        assertEquals(400, actualResponse.getStatus());
    }

    @Test
    public void crlImportShouldReturnBadRequestOnNonExistingCa() throws Exception {
        // given: an invalid CA CN
        final String issuerDn = "CN=InvalidCa";

        // when: importing CRL into a CA that doesn't exist.
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(issuerDn));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);

        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CA with DN: " + issuerDn + " does not exist.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnMissingFile() throws Exception {
        // when
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);

        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "No CRL file uploaded.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnIncorrectFileFormFieldName() throws Exception {
        // given
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        CaTestUtils.removeCrlByIssuerDn(TEST_ISSUER_DN1);
        assertNull(getLatestCrl(TEST_ISSUER_DN1));

        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl, "invalidFormFieldName").withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);

        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "No CRL file uploaded.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnInvalidPartitionIndex() throws Exception {
        // given: with invalid partition indexes, and valid crl file.
        // String decimalCrlPartitionIndex = "3.14";

        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        CaTestUtils.removeCrlByIssuerDn(TEST_ISSUER_DN1);
        assertNull(getLatestCrl(TEST_ISSUER_DN1));

        // when: negative number
        Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl).withInvalidCrlPartitionIndex("-1").build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        String actualJsonString = crlImportResponse.readEntity(String.class);
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: Partition index should be a number of 0 or greater.", actualJsonString);

        // when: non-numeric number
        crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl).withInvalidCrlPartitionIndex("one").build();
        crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        actualJsonString = crlImportResponse.readEntity(String.class);
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: Partition index should be a number of 0 or greater.", actualJsonString);

        // when decimalCrlPartitionIndex
        crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl).withInvalidCrlPartitionIndex("1.3").build();
        crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        actualJsonString = crlImportResponse.readEntity(String.class);
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Invalid CRL partition index: Partition index should be a number of 0 or greater.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestOnInvalidFileContent() throws Exception {
        // given: that we have invalid file contents and import
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFileContent("invalid").withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);
        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "Error while importing CRL: java.io.IOException: malformed PEM data: no header found", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnExceptionWithEmptyFileContent() throws Exception {
        // given: that we have an empty file contents and import
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withEmptyCrlFile().withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);
        // then
        assertProperJsonExceptionErrorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                "General failure.", actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestWhenFileIsIssuedByAnotherCa() throws Exception {
        // given: we create a CRL issued by CA "A"
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN2) + "/createcrl");
        final X509CRL x509CrlForOtherCA = getLatestCrl(TEST_ISSUER_DN2);

        // when: we try importing the CRL to CA "B"
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509CrlForOtherCA).withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);
        final String actualJsonString = crlImportResponse.readEntity(String.class);

        // then
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CRL is not issued by " + TEST_ISSUER_DN1, actualJsonString);
    }

    @Test
    public void crlImportShouldReturnBadRequestWhenUploadingAnOldCrl() throws Exception {
        // given: we create multiple CRL's
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl"); // CRL #1 - will attempt to upload again
        final X509CRL oldX509Crl = getLatestCrl(TEST_ISSUER_DN1);
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl"); // CRL #2 - latest in DB

        // when: we try to import old CRL
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(oldX509Crl).withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);

        // then
        final String actualJsonString = crlImportResponse.readEntity(String.class);
        assertEquals("Bad Request was expected", Status.BAD_REQUEST.getStatusCode(), crlImportResponse.getStatus());
        assertProperJsonExceptionErrorResponse(Status.BAD_REQUEST.getStatusCode(),
                "CRL #1 or higher is already in the database.", actualJsonString);
    }

    @Test
    public void crlImportShouldCreateANewCrl() throws Exception {
        // given: we create a CRL, store it to a file for the import test and delete the existing one from DB
        createCrl("/v1/ca/" + encodeUrl(TEST_ISSUER_DN1) + "/createcrl");
        final X509CRL x509Crl = getLatestCrl(TEST_ISSUER_DN1);
        CaTestUtils.removeCrlByIssuerDn(TEST_ISSUER_DN1);
        assertNull(getLatestCrl(TEST_ISSUER_DN1));

        // when: we import previously created CRL file
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl).withCrlPartitionIndex().build();
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);

        // then
        assertEquals("CRL import failed", Status.OK.getStatusCode(), crlImportResponse.getStatus());
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

        // when: we import previously created CRL file
        final Entity crlImportRequestEntity = new CrlImportEntityBuilder().withCrlFile(x509Crl).withCrlPartitionIndex(crlPartitionIndex).build();
        System.out.println("---- " + crlImportRequestEntity.toString());
        final WebTarget crlImportRequest = newRequest(getImportCrlPath(TEST_ISSUER_DN1));
        final Response crlImportResponse = crlImportRequest.request().post(crlImportRequestEntity);

        // then
        assertEquals("CRL import failed", Status.OK.getStatusCode(), crlImportResponse.getStatus());
        assertNotNull("New CRL was not returned by API /getLatestCrl", getLatestCrl(TEST_ISSUER_DN1, false, crlPartitionIndex));
    }

    public static class CrlImportEntityBuilder {
        private EntityPart crlPartitionIndexEP;
        private EntityPart crlFileEP;

        public CrlImportEntityBuilder() {}

        public CrlImportEntityBuilder withCrlPartitionIndex(final int crlPartitionIndex) throws IOException {
            this.crlPartitionIndexEP = EntityPart.withName("crlPartitionIndex").content((Integer) crlPartitionIndex, Integer.class).build();
            return this;
        }

        public CrlImportEntityBuilder withCrlPartitionIndex() throws IOException {
            return this.withCrlPartitionIndex(0);
        }

        public CrlImportEntityBuilder withInvalidCrlPartitionIndex(final String invalidCrlPartitionIndex) throws IOException {
            this.crlPartitionIndexEP = EntityPart.withName("crlPartitionIndex").content(invalidCrlPartitionIndex).build();
            return this;
        }

        public CrlImportEntityBuilder withCrlFile(final X509CRL crlFile) throws CRLException, IOException {
            return withCrlFile(crlFile, "crlFile");
        }

        public CrlImportEntityBuilder withCrlFile(final X509CRL crlFile, final String fieldName) throws CRLException, IOException {
            Files.write(Paths.get(CRL_FILENAME), crlFile.getEncoded());
            this.crlFileEP = EntityPart.withName(fieldName).fileName(CRL_FILENAME).content(new File(CRL_FILENAME)).build();
            return this;
        }

        public CrlImportEntityBuilder withEmptyCrlFile() throws CRLException, IOException {
            return this.withCrlFileContent("");
        }

        public CrlImportEntityBuilder withCrlFileContent(final String content) throws IOException {
            Files.write(Paths.get(CRL_FILENAME), content.getBytes());
            this.crlFileEP = EntityPart.withName("crlFile").fileName(CRL_FILENAME)
                    .content(new File(CRL_FILENAME))
                    .mediaType(MediaType.MULTIPART_FORM_DATA).build();
            return this;
        }

        public Entity build(){
            final List<EntityPart> entityParts = new ArrayList<>();

            if (crlFileEP != null) {
                entityParts.add(crlFileEP);
            }

            if (crlPartitionIndexEP != null) {
                entityParts.add(crlPartitionIndexEP);
            }
            final GenericEntity<List<EntityPart>> genericEntity = new GenericEntity<>(entityParts){};
            return Entity.entity(genericEntity, MediaType.MULTIPART_FORM_DATA);
        }
    }

    /**
     * Get the latest CRL via REST API /getLatestCrl
     * @param issuerDn Issuer DN
     * @param crlPartitionIndex CRL partition index number
     * @param deltaCrl false (full) or true (delta)
     * @return X509CRL certificate revocation list
     */
    private X509CRL getLatestCrl(String issuerDn, boolean deltaCrl, int crlPartitionIndex) throws Exception {
        final JSONParser jsonParser = new JSONParser();

        final WebTarget latestCrlRequest = newRequest("/v1/ca/" + encodeUrl(issuerDn) +
                "/getLatestCrl?deltaCrl=" + deltaCrl + "&crlPartitionIndex=" + crlPartitionIndex);

        final Response latestCRLResponse = latestCrlRequest.request().get();
        final JSONObject latestCRLResponseAsJSON = (JSONObject) jsonParser.parse(latestCRLResponse.readEntity(String.class));

        final Object latestCRL = latestCRLResponseAsJSON.get("crl");

        return latestCRL == null ? null : CertTools.getCRLfromByteArray(Base64.decode(latestCRL.toString().getBytes()));
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
