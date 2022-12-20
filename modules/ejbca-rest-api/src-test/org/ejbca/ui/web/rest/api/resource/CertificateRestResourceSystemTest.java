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
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
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
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
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
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TimeZone;

import static org.cesecore.certificates.crl.RevocationReasons.*;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * A unit test class for CertificateRestResource to test its content.
 */
public class CertificateRestResourceSystemTest extends RestResourceSystemTestBase {

    //private static final Logger log = Logger.getLogger(CertificateRestResourceSystemTest.class);
    private static final String CRL_FILENAME = "CertificateRestSystemTestCrlFile";
    private static final String ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE = "Certificate with issuer: {0} and serial " +
            "number: {1} has previously been revoked. Revocation reason could not be changed or was not allowed.";
    private static final JSONParser jsonParser = new JSONParser();

    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final UnidfnrProxySessionRemote unidfnrProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final Random random = new Random();
    private X509CA x509TestCa;
    private String testCaName = "CertificateRestSystemTestCa";
    private String testIssuerDn = "C=SE,CN=" + testCaName;
    private String testUsername = "CertificateRestSystemTestUser";
    private String testCertProfileName = "CertificateRestSystemTestCertProfile";
    private String testEeProfileName = "CertificateRestSystemTestEeProfile";

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
        final int randomSuffix = random.nextInt();
        testCaName += randomSuffix;
        testIssuerDn += randomSuffix;
        testUsername += randomSuffix;
        testCertProfileName += randomSuffix;
        testEeProfileName += randomSuffix;
        CryptoProviderTools.installBCProvider();
        x509TestCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, testIssuerDn);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (x509TestCa != null) {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, x509TestCa.getCAInfo());
        }
        try {
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, testUsername);
        } catch (Exception e) {
            // ignore
        }
        internalCertificateStoreSession.removeCertificatesByUsername(testUsername);
        certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName);
        endEntityProfileSessionRemote.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, testEeProfileName);
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
        final List<Integer> availableCas = new ArrayList<>();
        availableCas.add(x509TestCa.getCAId());
        certificateProfile.setAvailableCAs(availableCas);
        final int[] availableBitLengths = {4096};
        certificateProfile.setAvailableBitLengths(availableBitLengths);
        final String[] availableAlgorithms = {"RSA"};
        certificateProfile.setAvailableKeyAlgorithms(availableAlgorithms);
        int certProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);
        // when
        final Response actualResponse = newRequest("/v2/certificate/profile/" + testCertProfileName).request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String responseCertProfileId = actualJsonObject.get("certificate_profile_id").toString();
        JSONArray jsonArrayAlgs = (JSONArray) actualJsonObject.get("available_key_algs");
        String algorithms = (String) jsonArrayAlgs.get(0);
        JSONArray jsonArrayBitLengths = (JSONArray) actualJsonObject.get("available_bit_lenghts");
        long bitLengths = (long) jsonArrayBitLengths.get(0);
        JSONArray jsonArrayCas = (JSONArray) actualJsonObject.get("available_cas");
        String cas = (String) jsonArrayCas.get(0);
        // then
        assertEquals(Integer.toString(certProfileId), responseCertProfileId);
        assertEquals("RSA", algorithms);
        assertEquals(4096, bitLengths);
        assertEquals(testCaName, cas);
        assertJsonContentType(actualResponse);
    }


    @Test
    public void shouldRevokeCertificate() throws Exception {
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore();
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        // Attempt revocation through REST
        final Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE").request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        final String responseReason = (String) actualJsonObject.get("revocation_reason");

        // Verify rest response
        assertEquals(testIssuerDn, responseIssuerDn);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals("KEY_COMPROMISE", responseReason);

        // Verify actual database value
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        String databaseReason = RevocationReasons.getFromDatabaseValue(certificateData.getRevocationReason()).getStringValue();
        assertEquals("KEY_COMPROMISE", databaseReason);
    }

    @Test
    public void shouldAllowRevocationReasonChange() throws Exception {
        enableRevocationReasonChange();
        // User and certificate generation
        createTestEndEntity();
        final KeyStore keyStore = createKeystore();
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));

        // Attempt the initial revocation through REST
        Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=SUPERSEDED").request().put(null);
        String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);

        JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        String responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
        String responseSerialNr = (String) actualJsonObject.get("serial_number");
        boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        String responseReason = (String) actualJsonObject.get("revocation_reason");

        // Verify rest response
        assertEquals(testIssuerDn, responseIssuerDn);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals("SUPERSEDED", responseReason);

        // Verify actual database value
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        String databaseReason = RevocationReasons.getFromDatabaseValue(certificateData.getRevocationReason()).getStringValue();
        assertEquals("SUPERSEDED", databaseReason);

        // Second revocation for the same certificate.
        // Change revocation reason from SUPERSEDED to KEY_COMPROMISE with backdating
        actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE").request().put(null);
        actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);

        actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
        responseSerialNr = (String) actualJsonObject.get("serial_number");
        responseStatus = (boolean) actualJsonObject.get("revoked");
        responseReason = (String) actualJsonObject.get("revocation_reason");

        // Verify rest response
        assertEquals(testIssuerDn, responseIssuerDn);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals("KEY_COMPROMISE", responseReason);

        // Verify actual database value
        certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        databaseReason = RevocationReasons.getFromDatabaseValue(certificateData.getRevocationReason()).getStringValue();
        assertEquals("KEY_COMPROMISE", databaseReason);
    }

    @Test
    public void shouldPreventRevocationWithInvalidReason() throws Exception {
        // given
        final String serialNumber = generateTestSerialNumber();
        final String revocationReason = "sticky note with private key got lost";
        final int expectedErrorCode = 400;
        final String expectedErrorMessage = "Invalid revocation reason.";
        // when
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, revocationReason, null);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldPreventRevocationWithAFutureDate() throws Exception {
        // given
        final String serialNumber = generateTestSerialNumber();
        final String revocationDate = "3000-01-01T00:00:00Z";
        final int expectedErrorCode = 400;
        final String expectedErrorMessage = MessageFormat.format("Revocation date in the future: ''{0}''.", revocationDate);
        // when
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, KEYCOMPROMISE.getStringValue(), revocationDate);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldPreventRevocationReasonChangeIfDisabledOnCaLevel() throws Exception {
        // given
        disableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final int expectedErrorCode = 409;
        final String expectedErrorMessage = MessageFormat.format(ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE, testIssuerDn, serialNumber.toLowerCase());
        // when
        // perform initial revocation
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        // attempt to change revocation reason
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, KEYCOMPROMISE.getStringValue(), null);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldPreventBackdatingRevocationIfDisabledInCertificateProfile() throws Exception {
        // given
        disableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String revocationDate = "2000-01-01T00:00:00Z";
        final int expectedErrorCode = 422;
        final String expectedErrorMessage = MessageFormat.format("Back dated revocation not allowed for certificate profile ''{0}''." +
                " Certificate serialNumber ''{1}'', issuerDN ''{2}''.", testCertProfileName, serialNumber.toLowerCase(), testIssuerDn);
        // when
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, KEYCOMPROMISE.getStringValue(), revocationDate);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldPreserveRevocationDateWhenOnlyReasonIsChanged() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final String initialRevocationDate = initialRevocationResponse.get("revocation_date").toString();
        Thread.sleep(1000);
        final JSONObject revocationReasonChangeResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals("Changing revocation reson should have preserved the initial revocation date",
                initialRevocationDate, revocationReasonChangeResponse.get("revocation_date"));
    }

    @Test
    public void shouldAllowBackdatingRevocation() throws Exception {
        // given
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String revocationReason = SUPERSEDED.getStringValue();
        final String revocationDate = "2000-01-01T00:00:00Z";
        // when
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, revocationReason, revocationDate);
        // then
        assertEquals("Revocation date does not match with request", revocationDate, response.get("revocation_date"));
    }

    @Test
    public void shouldAllowBackdatingRevocationDuringReasonChange() throws Exception {
        // given
        enableRevocationReasonChange();
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String initialRevocationDate = "2000-01-01T00:00:00Z";
        final String newRevocationDate = "1999-01-01T00:00:00Z";
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, initialRevocationDate);
        final JSONObject revocationReasonChangeResponse = revokeCertificate(testIssuerDn, serialNumber, KEYCOMPROMISE.getStringValue(), newRevocationDate);
        // then
        assertEquals("Revocation date does not match with request", initialRevocationDate, initialRevocationResponse.get("revocation_date"));
        assertEquals("Revocation date had to be backdated", newRevocationDate, revocationReasonChangeResponse.get("revocation_date"));
    }

    @Test
    public void shouldAllowBackdatingRevokedCertificateWithReasonKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String revocationReason = KEYCOMPROMISE.getStringValue();
        final String initialRevocationDate = "2000-01-01T00:00:00Z";
        final String newRevocationDate = "1999-01-01T00:00:00Z";
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, revocationReason, initialRevocationDate);
        final JSONObject revocationReasonChangeResponse = revokeCertificate(testIssuerDn, serialNumber, revocationReason, newRevocationDate);
        // then
        assertEquals("Revocation date does not match with request", initialRevocationDate, initialRevocationResponse.get("revocation_date"));
        assertEquals("Revocation date had to be backdated", newRevocationDate, revocationReasonChangeResponse.get("revocation_date"));
    }

    @Test
    public void shouldAllowRevocationReasonChangeFromUnspecifiedToKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = UNSPECIFIED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final JSONObject updatedRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals(initialRevocationReason, initialRevocationResponse.get("revocation_reason"));
        assertEquals(updatedRevocationReason, updatedRevocationResponse.get("revocation_reason"));
    }

    @Test
    public void shouldAllowRevocationReasonChangeFromPrivilegesWithdrawnToKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = PRIVILEGESWITHDRAWN.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final JSONObject updatedRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals(initialRevocationReason, initialRevocationResponse.get("revocation_reason"));
        assertEquals(updatedRevocationReason, updatedRevocationResponse.get("revocation_reason"));
    }

    @Test
    public void shouldAllowRevocationReasonChangeFromCessationOfOperationToKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = CESSATIONOFOPERATION.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final JSONObject updatedRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals(initialRevocationReason, initialRevocationResponse.get("revocation_reason"));
        assertEquals(updatedRevocationReason, updatedRevocationResponse.get("revocation_reason"));
    }

    @Test
    public void shouldAllowRevocationReasonChangeFromAffiliationChangedToKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = AFFILIATIONCHANGED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final JSONObject updatedRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals(initialRevocationReason, initialRevocationResponse.get("revocation_reason"));
        assertEquals(updatedRevocationReason, updatedRevocationResponse.get("revocation_reason"));
    }

    @Test
    public void shouldAllowRevocationReasonChangeFromSupersededToKeyCompromise() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        final JSONObject initialRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final JSONObject updatedRevocationResponse = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertEquals(initialRevocationReason, initialRevocationResponse.get("revocation_reason"));
        assertEquals(updatedRevocationReason, updatedRevocationResponse.get("revocation_reason"));
    }

    @Test
    public void shouldPreventRevocationReasonChangeFromCaCompromiseToAnother() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = CACOMPROMISE.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        final int expectedErrorCode = 409;
        final String expectedErrorMessage = MessageFormat.format(ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE, testIssuerDn, serialNumber.toLowerCase());
        // when
        // perform initial revocation
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        // attempt to change revocation reason
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldPreventRevocationReasonChangeFromAACompromiseToAnother() throws Exception {
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = AACOMPROMISE.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        final int expectedErrorCode = 409;
        final String expectedErrorMessage = MessageFormat.format(ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE, testIssuerDn, serialNumber.toLowerCase());
        // when
        // perform initial revocation
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        // attempt to change revocation reason
        final JSONObject response = revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.toJSONString());
    }

    @Test
    public void shouldAllowReactivatingACertificateOnHold() throws Exception {
        // given
        createTestEndEntity();
        final KeyStore keyStore = createKeystore();
        final String serialNumber = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        final String fingerprint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final String revocationReason = CERTIFICATEHOLD.getStringValue();
        final String reactivationReason = NOT_REVOKED.getStringValue();
        // when
        final JSONObject revocationResponse = revokeCertificate(testIssuerDn, serialNumber, revocationReason, null);
        final Date preActivationSystemDate = new Date();
        Thread.sleep(1000);
        final JSONObject reactivationResponse = revokeCertificate(testIssuerDn, serialNumber, reactivationReason, null);
        final CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerprint);
        // then
        assertEquals("Revocation reason does not match with request", revocationReason, revocationResponse.get("revocation_reason"));
        assertEquals("Revocation reason does not match with request", reactivationReason, reactivationResponse.get("revocation_reason"));
        assertTrue("Wrong revocation status", (boolean) revocationResponse.get("revoked"));
        assertFalse("Wrong revocation status", (boolean) reactivationResponse.get("revoked"));
        assertNotNull("Revocation date does not match with request", revocationResponse.get("revocation_date"));
        assertNull("Revocation date should not be returned for an active certificate", reactivationResponse.get("revocation_date"));
        // reactivated certificates receive an updated revocation date in the DB to remove them from CRLs
        // and publish them even when "Publish only revoked certificates" setting is used
        assertTrue(certificateData.getRevocationDate() > preActivationSystemDate.getTime());
    }

    @Test
    public void shouldContainUpdatedRevocationReasonInBaseCrl() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final X509CRL initialCrl = createCrl(false);
        revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        final X509CRL updatedCrl = createCrl(false);
        // then
        assertEquals("Revocation reasons should match", initialRevocationReason, getRevocationReason(initialCrl, serialNumber));
        assertEquals("Revocation reasons should match", updatedRevocationReason, getRevocationReason(updatedCrl, serialNumber));
    }

    @Test
    public void shouldContainBackdatedRevocationDateInBaseCrl() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        final String initialRevocationDate = "2000-01-01T00:00:00Z";
        final String updatedRevocationDate = "1999-01-01T00:00:00Z";
        final long initialRevocationTime = DatatypeConverter.parseDateTime(initialRevocationDate).getTime().getTime();
        final long updatedRevocationTime = DatatypeConverter.parseDateTime(updatedRevocationDate).getTime().getTime();
        // when
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, initialRevocationDate);
        final X509CRL initialCrl = createCrl(false);
        revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, updatedRevocationDate);
        final X509CRL updatedCrl = createCrl(false);
        // then
        assertEquals("Revocation dates should match", initialRevocationTime, getRevocationTime(initialCrl, serialNumber));
        assertEquals("Revocation dates should match", updatedRevocationTime, getRevocationTime(updatedCrl, serialNumber));
    }

    @Test
    public void shouldContainUpdatedRevocationReasonInDeltaCrl() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        createCrl(false);
        Thread.sleep(1000);
        revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        final X509CRL deltaCrl = createCrl(true);
        // then
        assertEquals("Wrong revocation reason in Delta CRL", updatedRevocationReason, getRevocationReason(deltaCrl, serialNumber));
    }

    @Test
    public void shouldContainBackdatedRevocationDateInDeltaCrl() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // Scenario: base CRL > initial revocation > revocation backdating with a date after last base CRL > delta CRL
        // given
        enableRevocationReasonChange();
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String revocationReason = KEYCOMPROMISE.getStringValue();
        // when
        createCrl(false);
        Thread.sleep(1000);
        final String backdatedRevocationDate = getRevocationRequestDate();
        final long backdatedRevocationTime = DatatypeConverter.parseDateTime(backdatedRevocationDate).getTime().getTime();
        revokeCertificate(testIssuerDn, serialNumber, revocationReason, null); // revoke using sysdate
        Thread.sleep(1000);
        revokeCertificate(testIssuerDn, serialNumber, revocationReason, backdatedRevocationDate); // backdate
        final X509CRL deltaCrl = createCrl(true);
        // then
        assertNotNull("Certificate should be present in delta CRL", deltaCrl.getRevokedCertificate(CertTools.getSerialNumberFromString(serialNumber)));
        assertEquals("Revocation dates should match", backdatedRevocationTime, getRevocationTime(deltaCrl, serialNumber));
    }

    @Test
    public void shouldGenerateCrlUponRevocationReasonChange() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        enableGenerateCrlUponRevocation();
        final String serialNumber = generateTestSerialNumber();
        final String initialRevocationReason = SUPERSEDED.getStringValue();
        final String updatedRevocationReason = KEYCOMPROMISE.getStringValue();
        // when
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReason, null);
        final X509CRL initialCrl = getLatestCrl(false);
        revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        final X509CRL lastCrl = getLatestCrl(false);
        // then
        assertTrue("CRL number should be greater then the last", CrlExtensions.getCrlNumber(lastCrl).compareTo(CrlExtensions.getCrlNumber(initialCrl)) == 1);
        assertEquals("Revocation reasons should match", initialRevocationReason, getRevocationReason(initialCrl, serialNumber));
        assertEquals("Revocation reasons should match", updatedRevocationReason, getRevocationReason(lastCrl, serialNumber));
    }

    @Test
    public void shouldChangeRevocationReasonUponCrlImport() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        createTestEndEntity();
        final KeyStore keyStore = createKeystore();
        final String serialNumber = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        final String fingerprint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final RevocationReasons initialRevocationReasonInDb = SUPERSEDED;
        final RevocationReasons newRevocationReasonInCrl = KEYCOMPROMISE;
        // when
        revokeCertificate(testIssuerDn, serialNumber, initialRevocationReasonInDb.getStringValue(), null);
        final X509CRL crl = prepareImportCrl(fingerprint, newRevocationReasonInCrl);
        importCrl(crl);
        final CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerprint);
        // then
        assertEquals("Revocation reason did not change after CRL import", newRevocationReasonInCrl.getDatabaseValue(), certificateData.getRevocationReason());
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
                certificateAuthorityName(testCaName).
                certificateProfileName("ENDUSER").
                endEntityProfileName("EMPTY").
                username(testUsername).
                password("foo123").email(email).
                certificateRequest(csr).build();
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        
        // Send request
        final Response actualResponse = newRequest("/v1/certificate/pkcs10enroll").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String base64cert = (String) actualJsonObject.get("certificate");
        assertNotNull(base64cert);
        byte[] certBytes = Base64.decode(base64cert.getBytes());
        X509Certificate cert = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
        assertEquals("Returned certificate contained unexpected issuer", testIssuerDn, cert.getIssuerDN().getName());
        assertEquals("Returned certificate contained unexpected subject DN", "C=EE,ST=Alabama,L=tallinn,O=naabrivalve,CN=hello123server6", cert.getSubjectDN().getName());

        EndEntityInformation userData = endEntityAccessSession.findUser(INTERNAL_ADMIN_TOKEN, testUsername);
        assertEquals("Created user does not have expected email.", email, userData.getEmail());
    }
    
    @Test
    public void certificateRequestExpectCsrSubjectIgnored() throws Exception {
        // Add End Entity
        EndEntityInformation userdata = new EndEntityInformation(testUsername, "O=PrimeKey,CN=" + testUsername, x509TestCa.getCAId(), null,
            null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            SecConst.TOKEN_SOFT_BROWSERGEN, new ExtendedInformation());
        userdata.setPassword("foo123");
        userdata.setStatus(EndEntityConstants.STATUS_NEW);
        userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
        userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");        
        endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
        // Create CSR REST request
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(testCaName).
                username(testUsername).
                password("foo123").
                certificateRequest(csr).build();
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        
        // Send request
        final Response actualResponse = newRequest("/v1/certificate/certificaterequest").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String base64cert = (String) actualJsonObject.get("certificate");
        assertNotNull(base64cert);
        byte[] certBytes = Base64.decode(base64cert.getBytes());
        X509Certificate cert = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
        // Assert End Entity DN is used. CSR subject should be ignored.
        assertEquals("Returned certificate contained unexpected subject DN", "O=PrimeKey,CN=" + testUsername, cert.getSubjectDN().getName());
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
            EndEntityInformation userdata = new EndEntityInformation(testUsername, "CN=" + testUsername, x509TestCa.getCAId(), null, null, new EndEntityType(
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
            assertTrue("Alias is missing in keystore response", Collections.list(aliases).contains(testUsername));
            assertEquals("Unexpected response format", "PKCS12", responseFormat);
            assertEquals("Unexpected keystore format", "PKCS12-3DES-3DES", keyStore.getType());
        } finally {
            // Clean up
            approvalSession.removeApprovalRequest(INTERNAL_ADMIN_TOKEN, approvalId);
            approvalProfileSession.removeApprovalProfile(INTERNAL_ADMIN_TOKEN, profileId);
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

    /**
     * Revokes certificate via REST API
     */
    private JSONObject revokeCertificate(final String issuerDn, final String serialNumber, final String reason, final String date) throws Exception {
        assertNotNull("Missing Issuer DN value", issuerDn);
        assertNotNull("Missing Serial Number value", serialNumber);
        assertNotNull("Missing Revocation Reason value", reason);
        final String requestDate = (date != null) ? "&date=" + date : "";
        final String requestUriPath = MessageFormat.format("/v1/certificate/{0}/{1}/revoke/?reason={2}{3}",
                issuerDn, serialNumber, reason, requestDate);
        final Response actualResponse = newRequest(requestUriPath).request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);
        return (JSONObject) jsonParser.parse(actualJsonString);
    }

    /**
     * Enables "Allow changing revocation reason" setting for test CA
     */
    private void enableRevocationReasonChange() throws Exception {
        X509CAInfo caInfo = (X509CAInfo) x509TestCa.getCAInfo();
        caInfo.setAllowChangingRevocationReason(true);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, caInfo);
    }

    /**
     * Disables "Allow changing revocation reason" setting for test CA
     */
    private void disableRevocationReasonChange() throws Exception {
        X509CAInfo caInfo = (X509CAInfo) x509TestCa.getCAInfo();
        caInfo.setAllowChangingRevocationReason(false);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, caInfo);
    }

    /**
     * Enables "Generate CRL Upon Revocation" setting for test CA
     */
    private void enableGenerateCrlUponRevocation() throws Exception {
        X509CAInfo caInfo = (X509CAInfo) x509TestCa.getCAInfo();
        caInfo.setGenerateCrlUponRevocation(true);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, caInfo);
    }

    /**
     * Enables "Allow Backdated Revocation" setting for test certificate profile
     */
    private void enableRevocationBackdating() throws Exception {
        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setAllowBackdatedRevocation(true);
        certificateProfileSession.changeCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);
    }

    /**
     * Disables "Allow Backdated Revocation" setting for test certificate profile
     */
    private void disableRevocationBackdating() throws Exception {
        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setAllowBackdatedRevocation(false);
        certificateProfileSession.changeCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);
    }

    /**
     * Returns the test CertificateProfile. Creates one if needed.
     */
    private CertificateProfile getCertificateProfile() throws Exception {
        CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(testCertProfileName);
        if (certificateProfile == null) {
            final int certificateProfileId = createCertificateProfile();
            return certificateProfileSession.getCertificateProfile(certificateProfileId);
        }
        return certificateProfile;
    }

    /**
     * Creates a test certificate profile and returns its ID
     */
    private int createCertificateProfile() throws Exception {
        int certificateProfileId = certificateProfileSession.getCertificateProfileId(testCertProfileName);
        if (certificateProfileId == 0) {
            final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certificateProfile.setAvailableCAs(Arrays.asList(x509TestCa.getCAId()));
            certificateProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);
        }
        return certificateProfileId;
    }

    /**
     * Creates a test End Entity
     */
    private EndEntityInformation createTestEndEntity() throws Exception {
        final int certificateProfileId = createCertificateProfile();
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCAs(Arrays.asList(x509TestCa.getCAId()));
        endEntityProfile.setDefaultCA(x509TestCa.getCAId());
        final int endEntityProfileId = endEntityProfileSessionRemote.addEndEntityProfile(INTERNAL_ADMIN_TOKEN, testEeProfileName, endEntityProfile);
        final EndEntityInformation userdata = new EndEntityInformation(
                testUsername,
                "CN=" + testUsername,
                x509TestCa.getCAId(),
                null,
                null,
                new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                certificateProfileId,
                SecConst.TOKEN_SOFT_P12,
                new ExtendedInformation());
        userdata.setPassword("foo123");
        userdata.setStatus(EndEntityConstants.STATUS_NEW);
        userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
        userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
        userdata.setEndEntityProfileId(endEntityProfileId);
        return endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
    }

    /**
     * Creates a keystore with a certificate for the test End Entity
     */
    private KeyStore createKeystore() throws Exception {
        final byte[] keyStoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(
                INTERNAL_ADMIN_TOKEN,
                testUsername,
                "foo123",
                x509TestCa.getCAId(),
                "1024",
                "RSA",
                SecConst.TOKEN_SOFT_P12,
                false,
                false,
                false,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
        final KeyStore keyStore = KeyStore.getInstance("PKCS12-3DES-3DES");
        keyStore.load(new ByteArrayInputStream(keyStoreBytes), "foo123".toCharArray());
        return keyStore;
    }

    /**
     * Creates a test End Entity with a Certificate and returns its Serial Number
     */
    private String generateTestSerialNumber() throws Exception {
        createTestEndEntity();
        final KeyStore keyStore = createKeystore();
        return CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
    }

    /**
     * Creates a CRL for the test CA
     *
     * @param delta true for delta CRL, false for base CRL
     */
    private X509CRL createCrl(final boolean delta) throws Exception {
        final String orderedIssuerDn = CertTools.stringToBCDNString(testIssuerDn);
        final String deltaCrlParameter = (delta) ? "?deltacrl=true" : "";
        final Response createCrlResponse = newRequest("/v1/ca/" + orderedIssuerDn + "/createcrl" + deltaCrlParameter).request().post(null);
        assertEquals("Failed to create a CRL", 200, createCrlResponse.getStatus());
        return getLatestCrl(delta);
    }

    /**
     * Returns the latest CRL of test CA
     *
     * @param delta true for delta CRL, false for base CRL
     */
    private X509CRL getLatestCrl(final boolean delta) throws Exception {
        final String orderedIssuerDn = CertTools.stringToBCDNString(testIssuerDn);
        final String deltaCrlParameter = (delta) ? "?deltacrl=true" : "";
        // get the created CRL
        final Response getLatestCrlResponse = newRequest("/v1/ca/" + orderedIssuerDn + "/getLatestCrl" + deltaCrlParameter).request().get();
        assertEquals("Failed to retrieve latest CRL", 200, getLatestCrlResponse.getStatus());
        final Object latestCrlDer = getLatestCrlResponse.readEntity(Map.class).get("crl");
        assertNotNull("Response does not contain a CRL", latestCrlDer);
        return CertTools.getCRLfromByteArray(Base64.decode(latestCrlDer.toString().getBytes()));
    }

    /**
     * Extracts a certificate`s revocation reason from CRL
     *
     * @param crl          Certificate Revocation List
     * @param serialNumber Serial Number of certificate in CRL
     * @return String value of {@link java.security.cert.CRLReason CRLReason}
     */
    private String getRevocationReason(final X509CRL crl, final String serialNumber) {
        final X509CRLEntry crlEntry = crl.getRevokedCertificate(CertTools.getSerialNumberFromString(serialNumber));
        assertNotNull("Certificate not found in CRL", crlEntry);
        return crlEntry.getRevocationReason().toString();
    }

    /**
     * Extracts a certificate`s revocation time from CRL
     *
     * @param crl          Certificate Revocation List
     * @param serialNumber Serial Number of certificate in CRL
     * @return milliseconds between start of Unix Epoch and revocation date
     */
    private long getRevocationTime(final X509CRL crl, final String serialNumber) {
        final X509CRLEntry crlEntry = crl.getRevokedCertificate(CertTools.getSerialNumberFromString(serialNumber));
        assertNotNull("Certificate not found in CRL", crlEntry);
        return crlEntry.getRevocationDate().getTime();
    }

    /**
     * Returns formatted date string for invocation of revocation REST API
     *
     * @return ISO 8601 date string, e.g. 2000-01-01T00:00:00Z
     */
    private String getRevocationRequestDate() {
        final Calendar now = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        final String requestDateString = DatatypeConverter.printDateTime(now).replaceAll(".[0-9]{3}Z", "Z"); // remove milliseconds: .SSSZ > Z
        return requestDateString;
    }

    /**
     * Imports a X509CRL using REST API
     */
    private void importCrl(X509CRL crl) throws Exception {
        Files.write(Paths.get(CRL_FILENAME), crl.getEncoded());
        final MultipartEntityBuilder entity = MultipartEntityBuilder.create();
        entity.addBinaryBody("crlFile", new File(CRL_FILENAME), ContentType.DEFAULT_BINARY, CRL_FILENAME);
        final HttpPost request = new HttpPost(getBaseUrl() + "/v1/ca/" + CertTools.stringToBCDNString(testIssuerDn) + "/importcrl");
        request.setEntity(entity.build());
        final HttpResponse response = getHttpClient(true).execute(request);
        assertEquals("CRL import failed", Response.Status.OK.getStatusCode(), response.getStatusLine().getStatusCode());
        Files.deleteIfExists(Paths.get(CRL_FILENAME));
    }

    /**
     * Generates a new CRL containing a certificate with the desired revocation reason and deletes all CRLs of the test CA.
     *
     * @param fingerprint of certificate whose revocation reson should be changed
     * @param desiredRevocationReason new revocation reason in CRL
     * @return X509CRL containing certificate with the desired revocation reason
     * @throws Exception
     */
    private X509CRL prepareImportCrl(final String fingerprint, final RevocationReasons desiredRevocationReason) throws Exception {
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerprint);
        assertNotNull("Certificate not found", certificateData);
        final BigInteger serialNumber = CertTools.getSerialNumberFromString(certificateData.getSerialNumberHex());
        final int oldRevocationReason = certificateData.getRevocationReason();
        revokeCertificate(testIssuerDn, certificateData.getSerialNumberHex(), desiredRevocationReason.getStringValue(), null);
        final X509CRL crl = createCrl(false);
        assertNotNull("Certificate is not present in CRL", crl.getRevokedCertificate(serialNumber));
        assertEquals("Wrong revocation reason in CRL", desiredRevocationReason.getStringValue(),
                crl.getRevokedCertificate(serialNumber).getRevocationReason().toString());
        internalCertificateStoreSession.removeCRLs(INTERNAL_ADMIN_TOKEN, x509TestCa.getSubjectDN());
        internalCertificateStoreSession.setStatus(INTERNAL_ADMIN_TOKEN, fingerprint, oldRevocationReason);
        certificateData = internalCertificateStoreSession.getCertificateData(fingerprint);
        assertEquals("Revocation reason was not reverted", desiredRevocationReason.getDatabaseValue(), certificateData.getRevocationReason());
        return crl;
    }
}
