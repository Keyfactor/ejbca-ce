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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver;
import org.ejbca.ui.web.rest.api.io.request.Pagination;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CertificateStatus;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A test class for CertificateRestResource to test its content.
 */
public class CertificateRestResourceSearchCertificatesSystemTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(CertificateRestResourceSearchCertificatesSystemTest.class);
    private static final String TEST_CA_NAME = "RestCertificateResourceTestSearchCa";
    private static final String TEST_EEP_NAME = "RestCertificateResourceTestSearchEep";
    private static final String TEST_CERTP_NAME = "RestCertificateResourceTestSearchCertP";
    public static final DateFormat DATE_FORMAT_ISO8601 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final TimeZone TIME_ZONE_UTC = TimeZone.getTimeZone("UTC");

    private static X509CA x509TestCa;
    private static KeyPair keys;
    private static int certificateProfileId;
    private static int endEntityProfileId;
    private List<X509Certificate> certificates = new ArrayList<>();

    private static final JSONParser jsonParser = new JSONParser();
    private static final ObjectMapper objectMapper = new ObjectMapperContextResolver().getContext(null);

    private static CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private static EndEntityProfileSessionRemote endEntityProfileSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
        CryptoProviderTools.installBCProvider();
        x509TestCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, "C=SE,CN=" + TEST_CA_NAME);
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowValidityOverride(true);
        certificateProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERTP_NAME, profile);
        final EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+certificateProfileId);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, ""+certificateProfileId);
        eep.setValue(EndEntityProfile.AVAILCAS, 0, ""+x509TestCa.getCAId());
        eep.setValue(EndEntityProfile.DEFAULTCA, 0, ""+x509TestCa.getCAId());
        endEntityProfileId = endEntityProfileSessionRemote.addEndEntityProfile(INTERNAL_ADMIN_TOKEN, TEST_EEP_NAME, eep);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        DATE_FORMAT_ISO8601.setTimeZone(TIME_ZONE_UTC);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
        endEntityProfileSessionRemote.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, TEST_EEP_NAME);
        certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERTP_NAME);
        if (x509TestCa != null) {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, x509TestCa.getCAInfo());
        }
    }

    @After
    public void tearDown() {
        for(X509Certificate certificate : certificates) {
            removeCertificate(CertTools.getFingerprintAsString(certificate));
        }
        certificates.clear();
    }

    @Test
    public void shouldFindByUserNameEqual() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        String username = "searchCerUsername";
        X509Certificate certificate = createCertificate(username, "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .value(username)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final Object actualSerialNumber = actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");
        
        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected.", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);

    }

    @Test
    public void shouldFindByCnLike() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .value(expectedCn)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.LIKE.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        //when
        
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final Object actualSerialNumber = actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindByEndEntityProfile() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final Object actualSerialNumber = actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] actualCertBytes = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(actualCertBytes, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindByCertificateProfile() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.CERTIFICATE_PROFILE.name())
                .value(TEST_CERTP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .value(expectedCn)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.LIKE.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<SearchCertificateCriteriaRestRequest>();
        criterias.add(searchCertificateCriteriaRestRequest);
        criterias.add(searchCertificateCriteriaRestRequest2);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }


    @Test
    public void shouldFindByCA() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.CA.name())
                .value(TEST_CA_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindByCertificateStatus() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        // Create a new certificate, will have status active (20)
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        assertFindByCertificateStatus(expectedCn, expectedSerialNumber, SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_ACTIVE.name(), 1);
        // Change status to notified about expiration, this is a special status (21 instead of 20). We should still find it by a search for active certificates
        setCertificateStatus(CertTools.getFingerprintAsString(certificate), CertificateStatus.CERT_NOTIFIEDABOUTEXPIRATION.getStatusValue());
        assertFindByCertificateStatus(expectedCn, expectedSerialNumber, SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_ACTIVE.name(), 1); 
        // Search for revoked certificates instead, we should not find it
        assertFindByCertificateStatus(expectedCn, expectedSerialNumber, SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_REVOKED.name(), 0);
        // Set status to revoked, now we should find it again
        setCertificateStatus(CertTools.getFingerprintAsString(certificate), CertificateStatus.CERT_REVOKED.getStatusValue());
        assertFindByCertificateStatus(expectedCn, expectedSerialNumber, SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_REVOKED.name(), 1);
    }

    private void assertFindByCertificateStatus(String expectedCn, String expectedSerialNumber, String searchedStatus, int expectedSearchResult)
            throws Exception, JsonProcessingException, ParseException, CertificateParsingException {
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.STATUS.name())
                .value(searchedStatus)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<SearchCertificateCriteriaRestRequest>();
        criterias.add(searchCertificateCriteriaRestRequest);
        criterias.add(searchCertificateCriteriaRestRequest2);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        assertNotNull("Returned certificate should not be null", actualCertificates);
        assertEquals("The certificate search is expected to return a specified number of certificates", expectedSearchResult, actualCertificates.size());
        if (expectedSearchResult == 0) {
            // We can not go ahead and check the result if we expected to find 0 results, so break here
            return;
        }
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");
        
        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindCertificateByIssueDate() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, keys.getPublic());
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        Date date = new Date();
        String value = DATE_FORMAT_ISO8601.format(date);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.ISSUED_DATE.name())
                .value(value)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE.name())
                .build();
        date =new Date(System.currentTimeMillis() - 3600 * 1000);
        value = DATE_FORMAT_ISO8601.format(date);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest3 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.ISSUED_DATE.name())
                .value(value)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(searchCertificateCriteriaRestRequest);
        criterias.add(searchCertificateCriteriaRestRequest2);
        criterias.add(searchCertificateCriteriaRestRequest3);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindByCertificateByExpirationDate() throws Exception {
        ///given
        String expectedCn = "searchCertCn";
        Date date = new Date(System.currentTimeMillis() + 10 * 24 * 3600 * 1000);
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=" + expectedCn, date);
        String expectedSerialNumber = CertTools.getSerialNumberAsString(certificate);
        certificates.add(certificate);
        String expectedCertificateFormat = "DER";
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        date = new Date();
        String value = DATE_FORMAT_ISO8601.format(date);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.EXPIRE_DATE.name())
                .value(value)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER.name())
                .build();
        date = new Date(System.currentTimeMillis() + 15 * 24 * 3600 * 1000);
        value = DATE_FORMAT_ISO8601.format(date);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest3 = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.EXPIRE_DATE.name())
                .value(value)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(searchCertificateCriteriaRestRequest);
        criterias.add(searchCertificateCriteriaRestRequest2);
        criterias.add(searchCertificateCriteriaRestRequest3);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serial_number");
        final Object actualResponseFormat = actualCertificate0JsonObject.get("response_format");
        final String actualCertificateString = (String)actualCertificate0JsonObject.get("certificate");
        final String actualCertificateProfileName = (String)actualCertificate0JsonObject.get("certificate_profile");
        final String actualEndEntityProfileName = (String)actualCertificate0JsonObject.get("end_entity_profile");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertNotNull(actualCertificateString);

        byte [] certBytes2 = Base64.decode(Base64.decode(actualCertificateString.getBytes()));
        X509Certificate actualCertificate = CertTools.getCertfromByteArray(certBytes2, X509Certificate.class);
        String issuerDN = CertTools.getIssuerDN(actualCertificate);
        String actualCaName = CertTools.getPartFromDN(issuerDN, "CN");
        String actualSubjectDN = CertTools.getSubjectDN(actualCertificate);
        String actualCName = CertTools.getPartFromDN(actualSubjectDN, "CN");

        assertNotNull("Serial number not null.", actualSerialNumber);
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
        assertNotNull("Should have proper response.", actualResponseFormat);
        assertEquals("Should have proper response format.", expectedCertificateFormat, actualResponseFormat);
        assertNotNull("IssuerDN not null.", issuerDN);
        assertEquals("IssuerDN should be as expected.", TEST_CA_NAME, actualCaName);
        assertNotNull("SubjectDN not null.", actualSubjectDN);
        assertEquals("Common name should be as expected", expectedCn, actualCName);
        assertEquals("Certificate profile name should be as expected.", TEST_CERTP_NAME, actualCertificateProfileName);
        assertEquals("End entity profile name should be as expected.", TEST_EEP_NAME, actualEndEntityProfileName);
    }

    @Test
    public void shouldFindCertificateByUpdateTime() throws Exception {
        ///given
        String username = "searchByUpdateTimeUsername";
        Date updateTimeAfter = new Date(System.currentTimeMillis() - 1000);
        X509Certificate expectedCertificate = createCertificate(username, "C=SE,O=AnaTom,CN=searchCertCn", keys.getPublic());
        Date updateTimeBefore = new Date(System.currentTimeMillis() + 1000);
        String expectedSerialNumber = CertTools.getSerialNumberAsString(expectedCertificate);
        certificates.add(expectedCertificate);
        Thread.sleep(2000);
        X509Certificate laterCertificate = createCertificate(username, "C=SE,O=AnaTom,CN=searchCertCn", keys.getPublic());
        certificates.add(laterCertificate);
        final SearchCertificateCriteriaRestRequest usernameCriteria = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .value(username)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest updateTimeAfterCriteria = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.UPDATE_TIME.name())
                .value(DATE_FORMAT_ISO8601.format(updateTimeAfter))
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER.name())
                .build();
        final SearchCertificateCriteriaRestRequest updateTimeBeforeCriteria = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.UPDATE_TIME.name())
                .value(DATE_FORMAT_ISO8601.format(updateTimeBefore))
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(usernameCriteria);
        criterias.add(updateTimeAfterCriteria);
        criterias.add(updateTimeBeforeCriteria);
        Pagination pagination = new Pagination();
        pagination.setPageSize(10);
        pagination.setCurrentPage(1);
        final SearchCertificateCriteriaRequest searchCertificatesRestRequest = SearchCertificatesRestRequestV2.builder()
                .pagination(pagination)
                .criteria(criterias)
                .build();

        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v2/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");
        final JSONObject actualCertificate0JsonObject = (JSONObject) actualCertificates.get(0);
        final String actualSerialNumber = (String) actualCertificate0JsonObject.get("serialNumber");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals("Only one certificate should be found", 1, actualCertificates.size());
        assertEquals("Serial number should be as expected.", expectedSerialNumber, actualSerialNumber);
    }

    @Test
    public void shouldFindCertificateByUpdateTime_Negative() throws Exception {
        ///given
        Date updateTimeBefore = new Date(System.currentTimeMillis() - 1000);
        String username = "searchByUpdateTimeUsername2";
        X509Certificate certificate = createCertificate(username, "C=SE,O=AnaTom,CN=searchCertCn", keys.getPublic());
        certificates.add(certificate);
        final SearchCertificateCriteriaRestRequest usernameCriteria = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY.name())
                .value(username)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest updateTimeBeforeCriteria = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.UPDATE_TIME.name())
                .value(DATE_FORMAT_ISO8601.format(updateTimeBefore))
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(usernameCriteria);
        criterias.add(updateTimeBeforeCriteria);
        Pagination pagination = new Pagination();
        pagination.setPageSize(10);
        pagination.setCurrentPage(1);
        final SearchCertificateCriteriaRequest searchCertificatesRestRequest = SearchCertificatesRestRequestV2.builder()
                .pagination(pagination)
                .criteria(criterias)
                .build();

        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v2/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");

        //then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals("No certificates should be found", 0, actualCertificates.size());
    }

    @Test
    public void shouldFillMoreResultsFlagProperly() throws Exception {
        ///given
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=searchCertCn", keys.getPublic());
        certificates.add(certificate);
        KeyPair keys1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        certificate = createCertificate("searchCerUsername2", "C=SE,O=AnaTom,CN=searchCertCn2", keys1.getPublic());
        certificates.add(certificate);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(searchCertificateCriteriaRestRequest);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(1)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean moreResults  = (Boolean) actualJsonObject.get("more_results");
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");

        //then
        assertEquals("Shpuld have one result certificate",1, actualCertificates.size());
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertTrue("Should have more result", moreResults);
    }

    @Test
    public void shouldReturnEmptyList() throws Exception {
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        //when
//                .post();
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");

        //then
        assertEquals("Certificates list should be empty",0, actualCertificates.size());
    }

    @Test
    public void shouldReturnMoreThanOneResult() throws Exception {
        ///given
        X509Certificate certificate = createCertificate("searchCerUsername", "C=SE,O=AnaTom,CN=searchCertCn", keys.getPublic());
        certificates.add(certificate);
        KeyPair keys1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        certificate = createCertificate("searchCerUsername2", "C=SE,O=AnaTom,CN=searchCertCn2", keys1.getPublic());
        certificates.add(certificate);
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE.name())
                .value(TEST_EEP_NAME)
                .operation(SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL.name())
                .build();
        List<SearchCertificateCriteriaRestRequest> criterias = new ArrayList<>();
        criterias.add(searchCertificateCriteriaRestRequest);
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(10)
                .criteria(criterias)
                .build();
        //when
        final Entity<String> requestEntity = Entity.entity(objectMapper.writeValueAsString(searchCertificatesRestRequest), MediaType.APPLICATION_JSON);
        final Response actualResponse = newRequest("/v1/certificate/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificates = (JSONArray)actualJsonObject.get("certificates");

        //then
        assertEquals("Shpuld have one result certificate",2, actualCertificates.size());
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
    }

    private X509Certificate createCertificate(String username, String subjectDn, PublicKey publicKey) throws CertificateExtensionException, CustomCertificateSerialNumberException, IllegalKeyException, CertificateSerialNumberException, CertificateRevokeException, AuthorizationDeniedException, CADoesntExistsException, IllegalValidityException, CertificateCreateException, CryptoTokenOfflineException, IllegalNameException, InvalidAlgorithmException, SignRequestSignatureException, CAOfflineException {
        EndEntityInformation user = new EndEntityInformation(username, subjectDn, x509TestCa.getCAId(), null,
                "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certificateProfileId, EndEntityConstants.TOKEN_USERGEN, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");

        SimpleRequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword(), new Date());
        X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(INTERNAL_ADMIN_TOKEN, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        X509Certificate cert = (X509Certificate) resp.getCertificate();
        return cert;
    }

    private X509Certificate createCertificate(String username, String subjectDn, Date notAfter) throws CertificateExtensionException, CustomCertificateSerialNumberException, IllegalKeyException, CertificateSerialNumberException, CertificateRevokeException, AuthorizationDeniedException, CADoesntExistsException, IllegalValidityException, CertificateCreateException, CryptoTokenOfflineException, IllegalNameException, InvalidAlgorithmException, SignRequestSignatureException, CAOfflineException {
        EndEntityInformation user = new EndEntityInformation(username, subjectDn, x509TestCa.getCAId(), null,
                "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certificateProfileId, EndEntityConstants.TOKEN_USERGEN, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");

        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword(), notAfter);
        X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(INTERNAL_ADMIN_TOKEN, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        X509Certificate cert = (X509Certificate) resp.getCertificate();
        return cert;
    }

    private void removeCertificate(String fingerprint) {
        internalCertStoreSession.removeCertificate(fingerprint);
    }

    private void setCertificateStatus(String fingerprint, int status) throws AuthorizationDeniedException {
        internalCertStoreSession.setStatus(INTERNAL_ADMIN_TOKEN, fingerprint, status);
    }

}
