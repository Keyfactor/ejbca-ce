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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.unidfnr.UnidFnrHandlerMock;
import org.ejbca.core.ejb.unidfnr.UnidfnrProxySessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;
import org.ejbca.ui.web.rest.api.io.request.FinalizeRestRequest;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * A unit test class for CertificateRestResource to test its content.
 */
public class CertificateRestResourceSystemTest extends RestResourceSystemTestBase {

    //private static final Logger log = Logger.getLogger(CertificateRestResourceSystemTest.class);
    private static final String TEST_CA_NAME = "RestCertificateResourceTestCa";
    private static final String TEST_USERNAME = "CertificateRestSystemTestUser";
    private static final JSONParser jsonParser = new JSONParser();
    
    protected final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    protected final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final UnidfnrProxySessionRemote unidfnrProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST); 

    private static X509CA x509TestCa;

    private final String csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIDWDCCAkACAQAwYTELMAkGA1UEBhMCRUUxEDAOBgNVBAgTB0FsYWJhbWExEDAO\n"
            + "BgNVBAcTB3RhbGxpbm4xFDASBgNVBAoTC25hYWJyaXZhbHZlMRgwFgYDVQQDEw9o\n"
            + "ZWxsbzEyM3NlcnZlcjYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDe\n"
            + "lRzGyeXlCQL3lgLjzEn4qcbD0qtth8rXAwjg/eEN1u8lpQp3GtByWm6LeeB7CEyP\n"
            + "fyy+rW9C7nQmXvJ09cJaLAlETpGjjfZLy6pHzle/D192THB2MYZRuvvAPCfpjjnV\n"
            + "hP9sYn7GN7kCaYh61fvlD2fVquzqRdz9kjib3mVEmswkS6lHuAPIsmI7SG9UuvPR\n"
            + "ND1DOsmVwqOL62EOE/RlHRStxZDHQDoYMqZISAO5arpbDujn666IVqLs1QpsQ5Ih\n"
            + "Avxlw+EGNzzYMCbFEkuGs5JK/YNS7JL3JrvMor8XLngaatbteztK0o+khgT2K9x7\n"
            + "BCkqEoz9iJrmO3B8JDATAgMBAAGggbEwga4GCSqGSIb3DQEJDjGBoDCBnTBQBgNV\n"
            + "HREESTBHggtzb21lZG5zLmNvbYcEwKgBB4ISc29tZS5vdGhlci5kbnMuY29tpB4w\n"
            + "HDENMAsGA1UEAxMEVGVzdDELMAkGA1UEBxMCWFgwMQYDVR0lBCowKAYIKwYBBQUH\n"
            + "AwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQwCQYDVR0TBAIwADALBgNV\n"
            + "HQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAM2cW62D4D4vxaKVtIYpgolbD0zv\n"
            + "WyEA6iPa4Gg2MzeLJVswQoZXCj5gDOrttHDld3QQTDyT9GG0Vg8N8Tr9i44vUr7R\n"
            + "gK5w+PMq2ExGS48YrCoMqV+AJHaeXP+gi23ET5F6bIJnpM3ru6bbZC5IUE04YjG6\n"
            + "xQux6UsxQabuaTrHpExMgYjwJsekEVe13epUq5OiEh7xTJaSnsZm+Ja+MV2pn0gF\n"
            + "3V1hMBajTMGN9emWLR6pfj5P7QpVR4hkv3LvgCPf474pWA9l/4WiKBzrI76T5yz1\n"
            + "KoobCZQ2UrqnKFGEbdoNFchb2CDgdLnFu6Tbf6MW5zO5ypOIUih61Zf9Qyo=\n"
            + "-----END CERTIFICATE REQUEST-----\n";

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
        CryptoProviderTools.installBCProvider();
        x509TestCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, "C=SE,CN=" + TEST_CA_NAME);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (x509TestCa != null) {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, x509TestCa.getCAInfo());
        }
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final Response actualResponse = newRequest("/v1/certificate/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }
    
    @Test
    public void shouldReturnCertificateProfileInfo() throws Exception {
        //given
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        List<Integer> availableCas = new ArrayList<>();
        availableCas.add(x509TestCa.getCAId());
        certificateProfile.setAvailableCAs(availableCas);
        int[] availableBits = {4096};
        certificateProfile.setAvailableBitLengths(availableBits);
        String[] availableAlgorithms = {"RSA"};
        certificateProfile.setAvailableKeyAlgorithms(availableAlgorithms);
        certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, "TestProfileName", certificateProfile);
        try {
            // when
            final Response actualResponse = newRequest("/v2/certificate/profile/TestProfileName").request().get();
            final String actualJsonString = actualResponse.readEntity(String.class);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            JSONArray jsonArrayAlgs = (JSONArray) actualJsonObject.get("available_key_algs");
            String algs  = (String) jsonArrayAlgs.get(0);
            JSONArray jsonArrayBitLengths = (JSONArray) actualJsonObject.get("available_bit_lenghts");
            long bits  = (long) jsonArrayBitLengths.get(0);
            JSONArray jsonArrayCas = (JSONArray) actualJsonObject.get("available_cas");
            String cas  = (String) jsonArrayCas.get(0);
            // then
            assertEquals("RSA", algs);
            assertEquals(4096, bits);
            assertEquals(TEST_CA_NAME, cas);
            assertJsonContentType(actualResponse);
        } finally {
            certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, "TestProfileName");
        }
    }

    @Test
    public void shouldRevokeCertificate() throws Exception {
        try {
            // Create test user & generate certificate
            EndEntityInformation userdata = new EndEntityInformation(TEST_USERNAME, "CN=" + TEST_USERNAME, x509TestCa.getCAId(), null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, new ExtendedInformation());
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
            userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
            endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
            final byte[] keyStoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(INTERNAL_ADMIN_TOKEN, TEST_USERNAME, "foo123", x509TestCa.getCAId(),
                    "1024", "RSA", SecConst.TOKEN_SOFT_P12, false, false, false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            final KeyStore keyStore = KeyStore.getInstance("PKCS12-3DES-3DES");
            keyStore.load(new ByteArrayInputStream(keyStoreBytes), "foo123".toCharArray());
            String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(TEST_USERNAME));
            String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(TEST_USERNAME));
            String issuerDn = "C=SE,CN=" + TEST_CA_NAME;
            // Attempt revocation through REST
            final Response actualResponse = newRequest("/v1/certificate/" + issuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE").request().put(null);
            final String actualJsonString = actualResponse.readEntity(String.class);
            assertJsonContentType(actualResponse);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
            final String responseSerialNr = (String) actualJsonObject.get("serial_number");
            final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
            final String responseReason = (String) actualJsonObject.get("revocation_reason");

            // Verify rest response
            assertEquals(issuerDn, responseIssuerDn);
            assertEquals(serialNr, responseSerialNr);
            assertEquals(true, responseStatus);
            assertEquals("KEY_COMPROMISE", responseReason);

            // Verify actual database value
            CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
            String databaseReason = RevocationReasons.getFromDatabaseValue(certificateData.getRevocationReason()).getStringValue();
            assertEquals("KEY_COMPROMISE", databaseReason);
        } finally {
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, TEST_USERNAME);
            internalCertificateStoreSession.removeCertificatesByUsername(TEST_USERNAME);
        }
    }
    
    @Test
    public void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuerWithoutEmail() throws Exception {
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(null);
    }
    
    @Test
    public void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuerWithEmail() throws Exception {
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer("random@samp.de");
    }

    public void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(String email) throws Exception {
        // Create CSR REST request
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(TEST_CA_NAME).
                certificateProfileName("ENDUSER").
                endEntityProfileName("EMPTY").
                username(TEST_USERNAME).
                password("foo123").email(email).
                certificateRequest(csr).build();
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        
        // Send request
        try {
            final Response actualResponse = newRequest("/v1/certificate/pkcs10enroll").request().post(requestEntity);
            final String actualJsonString = actualResponse.readEntity(String.class);
            // Verify response
            assertJsonContentType(actualResponse);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String base64cert = (String) actualJsonObject.get("certificate");
            assertNotNull(base64cert);
            byte [] certBytes = Base64.decode(base64cert.getBytes());
            X509Certificate cert = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
            assertEquals("Returned certificate contained unexpected issuer", "C=SE,CN=RestCertificateResourceTestCa", cert.getIssuerDN().getName());
            assertEquals("Returned certificate contained unexpected subject DN", "C=EE,ST=Alabama,L=tallinn,O=naabrivalve,CN=hello123server6", cert.getSubjectDN().getName());
            
            EndEntityInformation userData = endEntityAccessSession.findUser(INTERNAL_ADMIN_TOKEN, TEST_USERNAME);
            assertEquals("Created user does not have expected email.", email, userData.getEmail());
        } finally {
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, TEST_USERNAME);
            internalCertificateStoreSession.removeCertificatesByUsername(TEST_USERNAME);
        }
    }
    
    @Test
    public void certificateRequestExpectCsrSubjectIgnored() throws Exception {
        // Add End Entity
        EndEntityInformation userdata = new EndEntityInformation(TEST_USERNAME, "O=PrimeKey,CN=" + TEST_USERNAME, x509TestCa.getCAId(), null, 
            null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            SecConst.TOKEN_SOFT_BROWSERGEN, new ExtendedInformation());
        userdata.setPassword("foo123");
        userdata.setStatus(EndEntityConstants.STATUS_NEW);
        userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
        userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");        
        endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
        // Create CSR REST request
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(TEST_CA_NAME).
                username(TEST_USERNAME).
                password("foo123").
                certificateRequest(csr).build();
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        
        // Send request
        try {
            final Response actualResponse = newRequest("/v1/certificate/certificaterequest").request().post(requestEntity);
            final String actualJsonString = actualResponse.readEntity(String.class);
            // Verify response
            assertJsonContentType(actualResponse);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String base64cert = (String) actualJsonObject.get("certificate");
            assertNotNull(base64cert);
            byte [] certBytes = Base64.decode(base64cert.getBytes());
            X509Certificate cert = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
            // Assert End Entity DN is used. CSR subject should be ignored.
            assertEquals("Returned certificate contained unexpected subject DN", "O=PrimeKey,CN=" + TEST_USERNAME, cert.getSubjectDN().getName());
        } finally {
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, TEST_USERNAME);
            internalCertificateStoreSession.removeCertificatesByUsername(TEST_USERNAME);
        }
    }

    @Test
    public void enrollPkcs10WithUnidFnr() throws Exception {

        final String username = "enrollPkcs10WithUnidFnr";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN="+username;
        
        final String profileNameUnidPrefix = "1234-5678-";
        final String profileName = profileNameUnidPrefix + "enrollPkcs10WithUnidFnr";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, profileName, certificateProfile);
        
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);       
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfileSession.addEndEntityProfile(INTERNAL_ADMIN_TOKEN, profileName, endEntityProfile);
        
        final String issuerDN = "CN=enrollPkcs10WithUnidFnrCa";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false, X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo testX509CaInfo = (X509CAInfo) testX509Ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testX509Ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(INTERNAL_ADMIN_TOKEN, testX509Ca);
        
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10CertificationRequest = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                CertTools.stringToBcX500Name(subjectDn), keys.getPublic(), null, keys.getPrivate(), null);   
        String unidFnrCsr = CertTools.buildCsr(pkcs10CertificationRequest);
        
        // Create CSR REST request
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(testX509CaInfo.getName()).
                certificateProfileName(profileName).
                endEntityProfileName(profileName).
                username(username).
                password(password).
                certificateRequest(unidFnrCsr).build();
        
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        // Send request
        try {
            final Response actualResponse = newRequest("/v1/certificate/pkcs10enroll").request().post(requestEntity);
            final String actualJsonString = actualResponse.readEntity(String.class);
            // Verify response
            assertJsonContentType(actualResponse);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String base64cert = (String) actualJsonObject.get("certificate");
            assertNotNull(base64cert);
            byte [] certBytes = Base64.decode(base64cert.getBytes());
            X509Certificate certificate = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
            final X500Name x500Name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            final String unid = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            final String resultingFnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(unid);
            assertNotNull("Unid value was not stored", fnr);
            assertEquals("FNR value was not correctly converted", fnr, resultingFnr); 
        } finally {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, testX509CaInfo);
            try {
                endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, username);
            } catch (NoSuchEndEntityException e) {
                //NOPMD ignore
            }
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            endEntityProfileSession.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, profileName);
            certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, profileName);
        }
    }

    @Test
    public void finalizeKeyStoreExpectPkcs12Response() throws Exception {
        // Create an add end entity approval request
        final AuthenticationToken approvalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaRestApiApprovalTestAdmin"));
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("Test Approval Profile");
        approvalProfile.setNumberOfApprovalsRequired(1);
        approvalProfile.initialize();
        int profileId = -1;
        int approvalId = -1;

        try {
            // Generate approval request
            profileId = approvalProfileSession.addApprovalProfile(INTERNAL_ADMIN_TOKEN, approvalProfile);
            LinkedHashMap<ApprovalRequestType, Integer> approvalsMap = new LinkedHashMap<>();
            approvalsMap.put(ApprovalRequestType.ADDEDITENDENTITY, profileId);
            x509TestCa.getCAInfo().setApprovals(approvalsMap);
            caSession.editCA(INTERNAL_ADMIN_TOKEN, x509TestCa.getCAInfo());
            EndEntityInformation userdata = new EndEntityInformation(TEST_USERNAME, "CN=" + TEST_USERNAME, x509TestCa.getCAId(), null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, new ExtendedInformation());
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
            userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
            int requestId = -1;
            try {
                endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
                fail("Expected WaitingForApprovalException");
            } catch (WaitingForApprovalException e) {
                requestId = e.getRequestId();
            }
            Approval approval = new Approval("REST System Test Approval", AccumulativeApprovalProfile.FIXED_STEP_ID ,
                    approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().
                    values().iterator().next().getPartitionIdentifier());
            approvalId = getApprovalDataNoAuth(requestId).getApprovalId();
            approvalExecutionSession.approve(approvalAdmin, approvalId, approval);

            // Attempt REST finalize
            final FinalizeRestRequest requestObject = new FinalizeRestRequest("P12", "foo123");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
            final Response actualResponse = newRequest("/v1/certificate/" + requestId + "/finalize").request().post(requestEntity);
            final String actualJsonString = actualResponse.readEntity(String.class);
            assertJsonContentType(actualResponse);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseFormat = (String) actualJsonObject.get("response_format");
            final String base64Keystore = (String) actualJsonObject.get("certificate");
            final byte[] keystoreBytes = Base64.decode(base64Keystore.getBytes());
            KeyStore keyStore = KeyStore.getInstance("PKCS12-3DES-3DES");
            keyStore.load(new ByteArrayInputStream(keystoreBytes), "foo123".toCharArray());
            // Verify results
            Enumeration<String> aliases = keyStore.aliases();
            assertEquals("Unexpected alias in keystore response", TEST_USERNAME, aliases.nextElement());
            assertEquals("Unexpected response format", "PKCS12", responseFormat);
            assertEquals("Unexpected keystore format", "PKCS12-3DES-3DES", keyStore.getType());
        } finally {
            // Clean up
            approvalSession.removeApprovalRequest(INTERNAL_ADMIN_TOKEN, approvalId);
            approvalProfileSession.removeApprovalProfile(INTERNAL_ADMIN_TOKEN, profileId);
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, TEST_USERNAME);
            internalCertificateStoreSession.removeCertificatesByUsername(TEST_USERNAME);
        }
    }

    private ApprovalDataVO getApprovalDataNoAuth(final int id) {
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));
        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalProxySession.query(query, 0, 100, "", "");
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval request failed: " + e.getMessage(), e);
        }
        if (approvals.isEmpty()) {
            return null;
        }
        return approvals.iterator().next();
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
        final Response actualResponse = newRequest("/v1/certificate/status").request().get();
        final int status = actualResponse.getStatus();
        // then
        assertEquals("Unexpected response after disabling protocol", 403, status);
        // restore state
        enableRestProtocolConfiguration();
    }
}
