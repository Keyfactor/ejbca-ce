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
import com.keyfactor.util.Base64;
import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.EntityPart;
import jakarta.ws.rs.core.GenericEntity;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CvcCA;
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
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
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
import org.ejbca.ui.web.rest.api.resource.util.CertificateRestResourceSystemTestUtil;
import org.ejbca.ui.web.rest.api.resource.util.TestEndEntityParamHolder;
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

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
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
import java.util.Random;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import static org.cesecore.certificates.crl.RevocationReasons.AACOMPROMISE;
import static org.cesecore.certificates.crl.RevocationReasons.AFFILIATIONCHANGED;
import static org.cesecore.certificates.crl.RevocationReasons.CACOMPROMISE;
import static org.cesecore.certificates.crl.RevocationReasons.CERTIFICATEHOLD;
import static org.cesecore.certificates.crl.RevocationReasons.CESSATIONOFOPERATION;
import static org.cesecore.certificates.crl.RevocationReasons.KEYCOMPROMISE;
import static org.cesecore.certificates.crl.RevocationReasons.NOT_REVOKED;
import static org.cesecore.certificates.crl.RevocationReasons.PRIVILEGESWITHDRAWN;
import static org.cesecore.certificates.crl.RevocationReasons.SUPERSEDED;
import static org.cesecore.certificates.crl.RevocationReasons.UNSPECIFIED;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * A unit test class for CertificateRestResource to test its content.
 */
public class CertificateRestResourceSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CertificateRestResourceSystemTest.class);

    private static final String CRL_FILENAME = "CertificateRestSystemTestCrlFile";
    private static final String ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE = "Certificate with issuer: {0} and serial " +
            "number: {1} has previously been revoked. Revocation reason could not be changed or was not allowed.";
    private static final String INVALIDITY_DATE_NOT_ALLOWED_BY_CA = "Invalidity date was given but not allowed by CA, {0}, {1}";

    private static final JSONParser jsonParser = new JSONParser();

    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final UnidfnrProxySessionRemote unidfnrProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final Random RANDOM = new Random();
    private X509CA x509TestCa;
    private String testCaName = "CertificateRestSystemTestCa";
    private String testIssuerDn = "C=SE,CN=" + testCaName;
    private String testUsername = "CertificateRestSystemTestUser";
    private String testCertProfileName = "CertificateRestSystemTestCertProfile";
    private String testEeProfileName = "CertificateRestSystemTestEeProfile";

    private CvcCA cvcTestCa = null; // Don't create this for every test
    private String testCaNameCVC = "TESTCVC";
    private String testCVCIssuerDn = "C=SE,CN=CAREF001";

    public static final String BEGIN_CSR = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CSR = "-----END CERTIFICATE REQUEST-----";
    private static final String CSR_WITHOUT_HEADERS =
            "MIIDWDCCAkACAQAwYTELMAkGA1UEBhMCRUUxEDAOBgNVBAgTB0FsYWJhbWExEDAO\n"
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
                    + "KoobCZQ2UrqnKFGEbdoNFchb2CDgdLnFu6Tbf6MW5zO5ypOIUih61Zf9Qyo=";

    private static final String CSR_WITH_HEADERS =
            BEGIN_CSR
                    + "\n"
                    + CSR_WITHOUT_HEADERS
                    + "\n"
                    + END_CSR;

    private static final String CSRF_OR_CVC_WITHOUT_HEADERS =
            "MIICZjCCAU4CAQAwITELMAkGA1UEBhMCU0UxEjAQBgNVBAMMCVJFU1RDVkMwMTCC\n"
                    + "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwSr/BRjyNpdZWfRnRYbA/7\n"
                    + "CwYpehZglkdJyruafcs0QOMed9wXeuVCVUbIO413XdBV89TzM0zqadOwnJoSIC2X\n"
                    + "Nq6c++Lkg0bi9q/ZDtAN2OIhYQ7n+gww8MDdi9UfOyuaD97LBh87vXpi+0BEuP2c\n"
                    + "IbbIckSlvYf3ZTarx1sLdFF1PfnHleoczCKONGVSax+PFvDROqUVq79hM+yn1cAP\n"
                    + "Pnnl+1oJsPUbKgX8974ZqjUQDkIWP1y2thrqDDlrbHh0xYIEAwkU55zzbPX0Zw19\n"
                    + "GWFzQ01nhnyhJ9urbFvJpOOge4KZe0TKzz0Mo7tnqrsjO+GP7kDRgHZ9UNNkEZMC\n"
                    + "AwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQB3TuQNy1Xn2bJc1rnOLFcgBvDpHmdI\n"
                    + "NSGCL8xJdvI5G5268uZy1I3l8Jgwi33y3wltBLR0DK4ry0u5S3NxLPpU+0XwwWE7\n"
                    + "p+oCBDziRUQeUGptSAsUJ2qZZtyzPbcT5IYitiyrfHFE9LkDOa9cOajFuny+dQsO\n"
                    + "yJ6fzt0/CozD1WehsukRBe78X2M0Il5TPa0WcaPr8KmN0MFnuH+hEyg8LyLfOlo4\n"
                    + "Om5wKtLQTrVIxwQhRuUDRKZ33k0+IsYSGf6E/sG340MpYgouYgckOim7u2s/zr0w\n"
                    + "dNYMlBxLD8HH+SfOVVqQ3mITkw/WOPDGoBe28E5TJoWAA+yu9I7lLQ7d";

    // A PKCS#10 request with a CN of max 9 characters to fit into a CVC Mnemonic.
    // Subject: C = SE, CN = RESTCVC01
    private static final String CSRF_OR_CVC_WITH_HEADERS =
            BEGIN_CSR
                    + "\n"
                    + CSRF_OR_CVC_WITHOUT_HEADERS
                    + "\n"
                    + END_CSR;

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
        final int randomSuffix = RANDOM.nextInt();
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
        if (cvcTestCa != null) {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, cvcTestCa.getCAInfo());
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
        // Given
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        final List<Integer> availableCas = new ArrayList<>();
        availableCas.add(x509TestCa.getCAId());
        certificateProfile.setAvailableCAs(availableCas);

        final int[] availableBitLengths = { 4096 };
        certificateProfile.setAvailableBitLengths(availableBitLengths);

        final String[] availableAlgorithms = { "RSA" };
        certificateProfile.setAvailableKeyAlgorithms(availableAlgorithms);

        final String[] availableAltAlgorithms = {"KYBER768", "ML-DSA-65"};
        certificateProfile.setUseAlternativeSignature(true);
        certificateProfile.setAlternativeAvailableKeyAlgorithms(availableAltAlgorithms);

        int certProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);

        // When
        final Response actualResponse = newRequest("/v2/certificate/profile/" + testCertProfileName).request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        final String responseCertProfileId = actualJsonObject.get("certificate_profile_id").toString();

        final JSONArray jsonArrayAlgorithms = (JSONArray) actualJsonObject.get("available_key_algs");
        final String algorithms = (String) jsonArrayAlgorithms.get(0);

        final JSONArray jsonArrayBitLengths = (JSONArray) actualJsonObject.get("available_bit_lenghts");
        final long bitLengths = (long) jsonArrayBitLengths.get(0);

        final JSONArray jsonArrayAlternativeAlgorithms = (JSONArray) actualJsonObject.get("available_alt_key_algs");
        final String alternativeAlgorithm = (String) jsonArrayAlternativeAlgorithms.get(0);

        final JSONArray jsonArrayCas = (JSONArray) actualJsonObject.get("available_cas");
        final String cas = (String) jsonArrayCas.get(0);

        // then
        assertEquals(Integer.toString(certProfileId), responseCertProfileId);
        assertEquals("RSA", algorithms);
        assertEquals(4096, bitLengths);
        assertEquals("KYBER768", alternativeAlgorithm);
        assertEquals(testCaName, cas);
        assertJsonContentType(actualResponse);
    }

    @Test
    @SuppressWarnings("unused")
    public void shouldNotReturnAltKeysIfNotUsed() throws Exception {
        // Given
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        final List<Integer> availableCas = new ArrayList<>();
        availableCas.add(x509TestCa.getCAId());
        certificateProfile.setAvailableCAs(availableCas);

        final int[] availableBitLengths = { 4096 };
        certificateProfile.setAvailableBitLengths(availableBitLengths);

        final String[] availableAlgorithms = { "RSA" };
        certificateProfile.setAvailableKeyAlgorithms(availableAlgorithms);

        final String[] availableAltAlgorithms = {"KYBER768", "ML-DSA-65"};
        // Alternative signature is NOT used.
        certificateProfile.setUseAlternativeSignature(false);
        certificateProfile.setAlternativeAvailableKeyAlgorithms(availableAltAlgorithms);

        final int certProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);

        // When
        final Response actualResponse = newRequest("/v2/certificate/profile/" + testCertProfileName).request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        final JSONArray jsonArrayAlternativeAlgorithms = (JSONArray) actualJsonObject.get("available_alt_key_algs");

        // Then
        assertNull("No alternative key algorithms should have been returned", jsonArrayAlternativeAlgorithms);
    }

    @Test
    @SuppressWarnings("unused")
    public void shouldReturnEmptyAltKeysListIfNoneSelected() throws Exception {
        // Given
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        final List<Integer> availableCas = new ArrayList<>();
        availableCas.add(x509TestCa.getCAId());
        certificateProfile.setAvailableCAs(availableCas);

        final int[] availableBitLengths = { 4096 };
        certificateProfile.setAvailableBitLengths(availableBitLengths);

        final String[] availableAlgorithms = { "RSA" };
        certificateProfile.setAvailableKeyAlgorithms(availableAlgorithms);

        certificateProfile.setUseAlternativeSignature(true);
        certificateProfile.setAlternativeAvailableKeyAlgorithms(new String[0]);

        final int certProfileId = certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName, certificateProfile);

        // When
        final Response actualResponse = newRequest("/v2/certificate/profile/" + testCertProfileName).request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        final JSONArray jsonArrayAlternativeAlgorithms = (JSONArray) actualJsonObject.get("available_alt_key_algs");

        // Then
        assertNotNull("Alternative key algorithms should have been returned", jsonArrayAlternativeAlgorithms);
        assertEquals("Alternative key algorithms list should be empty", 0, jsonArrayAlternativeAlgorithms.size());
    }

    @Test
    public void shouldRevokeCertificateWithRsaKey() throws Exception {
        createTestEndEntity();
        revokeCertificate(createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA));
    }
    
    @Test
    public void shouldRevokeCertificateMLDSA44() throws Exception {
        createTestEndEntity();
        revokeCertificate(createKeystore(AlgorithmConstants.SIGALG_MLDSA44, AlgorithmConstants.KEYALGORITHM_MLDSA44));
    }
    
    @Test
    public void shouldRevokeCertificateFalcon512() throws Exception {
        createTestEndEntity();
        revokeCertificate(createKeystore(AlgorithmConstants.SIGALG_FALCON512, AlgorithmConstants.KEYALGORITHM_FALCON512));
    }
    
    private void revokeCertificate(final KeyStore keyStore) throws Exception {
        // Generate certificate
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
    public void shouldRevokeCertificateWithInvalidityDate() throws Exception {
        // given
        enableInvalidityDate();
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final String invalidityDateString = getRevocationRequestDate();
        final long invalidityDatelong = DatatypeConverter.parseDateTime(invalidityDateString).getTime().getTime();

        // when
        // Attempt revocation through REST with invalidity date
        final Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE&invalidity_date=" + invalidityDateString).request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        final String responseInvalidityDate = (String) actualJsonObject.get("invalidity_date");

        // then
        // Verify rest response
        assertEquals(testIssuerDn, responseIssuerDn);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals(invalidityDateString, responseInvalidityDate);
        // Verify actual database value
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        final long databaseInvalidityDate = certificateData.getInvalidityDateNeverNull();
        assertEquals(invalidityDatelong, databaseInvalidityDate);
    }

    @Test
    public void shouldAddInvalidityDateToRevokedCertificate() throws Exception {
        // given
        enableInvalidityDate();
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final String invalidityDateString = getRevocationRequestDate();
        final long invalidityDatelong = DatatypeConverter.parseDateTime(invalidityDateString).getTime().getTime();

        // when
        // We must first revoke the certificate to be able to use invalidity date without sending a revocation reason at the same time...
        newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE").request().put(null);
        // Verify we are allowed to add / change invalidity date when change of revocation reason is not allowed
        disableRevocationReasonChange();
        final Response actualResponse2 = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?invalidity_date=" + invalidityDateString).request().put(null);
        final String actualJsonString = actualResponse2.readEntity(String.class);
        assertJsonContentType(actualResponse2);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String responseIssuerDn = (String) actualJsonObject.get("issuer_dn");
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        final String responseInvalidityDate = (String) actualJsonObject.get("invalidity_date");

        // then
        // Verify rest response
        assertEquals(testIssuerDn, responseIssuerDn);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals(invalidityDateString, responseInvalidityDate);
        // Verify actual database value
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        final long databaseInvalidityDate = certificateData.getInvalidityDateNeverNull();
        assertEquals(invalidityDatelong, databaseInvalidityDate);
    }

    @Test
    public void shouldAllowInvalidityDateChange() throws Exception {
        // given
        enableInvalidityDate();
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        final String invalidityDateString = getRevocationRequestDate();
        TimeUnit.MILLISECONDS.sleep(1200);
        final String invalidityDateUpdateString = getRevocationRequestDate();

        // when
        // We must first revoke the certificate with initial invalidity date
        final Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE&invalidity_date=" + invalidityDateString).request().put(null);
        // Verify we are allowed to add / change invalidity date, even when change of revocation reason is not allowed
        final Response actualResponse2 = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?invalidity_date=" + invalidityDateUpdateString).request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final String actualJsonString2 = actualResponse2.readEntity(String.class);
        assertJsonContentType(actualResponse);
        assertJsonContentType(actualResponse2);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject actualJsonObject2 = (JSONObject) jsonParser.parse(actualJsonString2);
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        final String responseRevocationDate = (String) actualJsonObject.get("revocation_date");
        final String responseInvalidityDate = (String) actualJsonObject.get("invalidity_date");

        // Get invalidity date and revocation date from 2nd response 
        final String responseInvalidityDateUpdate = (String) actualJsonObject2.get("invalidity_date");
        final String responseRevocationDateAfterUpdate = (String) actualJsonObject2.get("revocation_date");

        // then
        // Verify 1st rest response
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals(invalidityDateString, responseInvalidityDate);
        assertEquals(responseRevocationDate, responseRevocationDateAfterUpdate);
        // Assert that we have given different dates at revoke and update
        assertNotEquals(invalidityDateString, invalidityDateUpdateString);
        // Assert that the date from the 1st response is not the same date as the date from the 2nd response 
        assertNotEquals(responseInvalidityDate, responseInvalidityDateUpdate);
        // Assert that the date we wanted to update to is the same as the date in the response
        assertEquals(invalidityDateUpdateString, responseInvalidityDateUpdate);
    }

    @Test
    public void shouldPreventRevocationWithAFutureInvalidityDate() throws Exception {
        // given
        final String serialNumber = generateTestSerialNumber();
        final String invalidityDate = "3000-01-01T00:00:00Z";
        final int expectedErrorCode = 400;
        final String expectedErrorMessage = MessageFormat.format("Date in the future: ''{0}''.", invalidityDate);
        // when
        final Response response = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNumber + "/revoke/?reason=KEY_COMPROMISE&invalidity_date=" + invalidityDate).request().put(null);
        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.readEntity(String.class));
    }

    @Test
    public void shouldPreventRevocationWithInvalidityDateIfDisabledOnCaLevel() throws Exception {
        // given
        disableInvalidityDate();
        final String invalidityDate = "2023-01-01T00:00:00Z";
        final String serialNumber = generateTestSerialNumber();
        final int expectedErrorCode = 409;
        final String expectedErrorMessage = MessageFormat.format(INVALIDITY_DATE_NOT_ALLOWED_BY_CA, testIssuerDn, serialNumber.toLowerCase());

        // when
        // try perform revocation
        final Response response = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNumber + "/revoke/?reason=KEY_COMPROMISE&invalidity_date=" + invalidityDate).request().put(null);

        // then
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, response.readEntity(String.class));
    }

    @Test
    public void shouldPreserveInvalidityDateWhenOnlyRevocationReasonIsChanged() throws Exception {
        // given
        enableInvalidityDate();
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final String invalidityDateString = getRevocationRequestDate();
        TimeUnit.MILLISECONDS.sleep(1200);

        // when
        final Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=SUPERSEDED&invalidity_date=" + invalidityDateString).request().put(null);
        // Get invalidity date value from data base
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        long dataBaseInvalidityDate = certificateData.getInvalidityDateNeverNull();
        // Now change reason
        final Response actualResponse2 = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE").request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final String actualJsonString2 = actualResponse2.readEntity(String.class);
        assertJsonContentType(actualResponse);
        assertJsonContentType(actualResponse2);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject actualJsonObject2 = (JSONObject) jsonParser.parse(actualJsonString2);
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        //final String responseInvalidityDate = (String) actualJsonObject.get("invalidity_date");
        // Get invalidity date from 2nd response 
        final String responseInvalidityDateUpdate = (String) actualJsonObject2.get("invalidity_date");
        // Get invalidity date value from database
        CertificateData certificateData2 = internalCertificateStoreSession.getCertificateData(fingerPrint);
        long dataBaseInvalidityDateAfterRevocationReasonChange = certificateData2.getInvalidityDateNeverNull();

        // then
        // verify rest response
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
        assertEquals(null, responseInvalidityDateUpdate);// we have not updated invalidity date...
        // verify actual database value of invalidity date not changed after only revocation reason change
        assertEquals(dataBaseInvalidityDate, dataBaseInvalidityDateAfterRevocationReasonChange);
    }

    @Test
    public void shouldPreventAnyInvalidityDateChangeWhenRevocationReasonChangeFails() throws Exception {
        // given
        enableInvalidityDate();
        // Create test user & generate certificate
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String serialNr = CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
        String fingerPrint = CertTools.getFingerprintAsString(keyStore.getCertificate(testUsername));
        final int expectedErrorCode = 409;
        final String expectedErrorMessage = MessageFormat.format(ALREADY_REVOKED_ERROR_MESSAGE_TEMPLATE, testIssuerDn, serialNr.toLowerCase());
        final String invalidityDateString = getRevocationRequestDate();
        TimeUnit.MILLISECONDS.sleep(1200);
        final String invalidityDateUpdateString = getRevocationRequestDate();

        // when
        final Response actualResponse = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=SUPERSEDED&invalidity_date=" + invalidityDateString).request().put(null);
        // Verify actual database value
        CertificateData certificateData = internalCertificateStoreSession.getCertificateData(fingerPrint);
        long dataBaseInvalidityDate = certificateData.getInvalidityDateNeverNull();
        disableRevocationReasonChange();

        // Try to update revocation reason, it is not allowed and should fail
        final Response actualResponse2 = newRequest("/v1/certificate/" + testIssuerDn + "/" + serialNr + "/revoke/?reason=KEY_COMPROMISE&invalidity_date=" + invalidityDateUpdateString).request().put(null);
        final String actualJsonString = actualResponse.readEntity(String.class);
        final String actualJsonString2 = actualResponse2.readEntity(String.class);
        assertJsonContentType(actualResponse);
        assertJsonContentType(actualResponse2);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject actualJsonObject2 = (JSONObject) jsonParser.parse(actualJsonString2);

        // then
        // Verify expected failure         
        assertProperJsonExceptionErrorResponse(expectedErrorCode, expectedErrorMessage, actualJsonObject2.toJSONString());
        CertificateData certificateData2 = internalCertificateStoreSession.getCertificateData(fingerPrint);
        long dataBasenvalidityDateAfterFailedRevocationReasonChange = certificateData2.getInvalidityDateNeverNull();
        final String responseSerialNr = (String) actualJsonObject.get("serial_number");
        final boolean responseStatus = (boolean) actualJsonObject.get("revoked");
        String responseReason = (String) actualJsonObject2.get("revocation_reason");
        assertNotEquals("KEY_COMPROMISE", responseReason);
        assertNotEquals(invalidityDateString, invalidityDateUpdateString);
        // Verify no change to invalidity date in database since change of revocation reason failed
        assertEquals(dataBaseInvalidityDate, dataBasenvalidityDateAfterFailedRevocationReasonChange);
        assertEquals(serialNr, responseSerialNr);
        assertEquals(true, responseStatus);
    }

    @Test
    public void shouldAllowRevocationReasonChange() throws Exception {
        enableRevocationReasonChange();
        // User and certificate generation
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        final String expectedErrorMessage = MessageFormat.format("Date in the future: ''{0}''.", revocationDate);
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
                        " Certificate serialNumber ''{1}'', issuerDN ''{2}''.", testCertProfileName, serialNumber.toLowerCase(),
                testIssuerDn);
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
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        Thread.sleep(1000);
        revokeCertificate(testIssuerDn, serialNumber, updatedRevocationReason, null);
        createCrl(false);
        final X509CRL deltaCrl = createCrl(true);
        // then
        assertEquals("Wrong revocation reason in Delta CRL", updatedRevocationReason, getRevocationReason(deltaCrl, serialNumber));
    }

    @Test
    public void shouldContainBackdatedRevocationDateInDeltaCrl() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // Scenario: initial revocation > revocation backdating with a date after last base CRL > base CRL > delta CRL
        // given
        enableRevocationReasonChange();
        enableRevocationBackdating();
        final String serialNumber = generateTestSerialNumber();
        final String revocationReason = KEYCOMPROMISE.getStringValue();
        // when
        Thread.sleep(1000);
        final String backdatedRevocationDate = getRevocationRequestDate();
        final long backdatedRevocationTime = DatatypeConverter.parseDateTime(backdatedRevocationDate).getTime().getTime();
        revokeCertificate(testIssuerDn, serialNumber, revocationReason, null); // revoke using sysdate
        Thread.sleep(1000);
        revokeCertificate(testIssuerDn, serialNumber, revocationReason, backdatedRevocationDate); // backdate
        createCrl(false);
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
        assertTrue("CRL number should be greater then the last", CrlExtensions.getCrlNumber(lastCrl).compareTo(CrlExtensions.getCrlNumber(initialCrl)) > 0);
        assertEquals("Revocation reasons should match", initialRevocationReason, getRevocationReason(initialCrl, serialNumber));
        assertEquals("Revocation reasons should match", updatedRevocationReason, getRevocationReason(lastCrl, serialNumber));
    }

    @Test
    public void shouldChangeRevocationReasonUponCrlImport() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        // given
        enableRevocationReasonChange();
        createTestEndEntity();
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(null, false, true);
    }

    @Test
    public void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuerWithoutHeaders() throws Exception {
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer("random@samp.de", false, false);
    }

    @Test
    public void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuerWithEmail() throws Exception {
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer("random@samp.de", false, true);
    }

    @Test
    public void enrollPkcs10ExpectCertificateResponseWithCVC() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        cvcTestCa = CryptoTokenTestUtils.createTestCVCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, testCVCIssuerDn);
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(null, true, true);
    }

    @Test
    public void enrollPkcs10ExpectCertificateResponseWithoutHeadersWithCVC() throws Exception {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        cvcTestCa = CryptoTokenTestUtils.createTestCVCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, testCVCIssuerDn);
        enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(null, true, false);
    }

    private void enrollPkcs10ExpectCertificateResponseWithRequestedSubjectDnAndIssuer(String email, boolean cvc, boolean withHeaders) throws Exception {

        String certificateRequest;
        if(cvc){
            certificateRequest = withHeaders ? CSRF_OR_CVC_WITH_HEADERS : CSRF_OR_CVC_WITHOUT_HEADERS;
        } else{
            certificateRequest = withHeaders ? CSR_WITH_HEADERS : CSR_WITHOUT_HEADERS;
        }

        // Create CSR REST request
        final String testCA = (cvc ? testCaNameCVC : testCaName);
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(testCA).
                certificateProfileName("ENDUSER").
                endEntityProfileName("EMPTY").
                username(testUsername).
                password("foo123").
                email(email).
                responseFormat("DER").
                certificateRequest(certificateRequest).build();
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
        Certificate cert = CertTools.getCertfromByteArray(certBytes, Certificate.class);
        if (cvc) {
            assertEquals("Cert type should be CVC", cert.getType(), "CVC");
        } else {
            assertEquals("Cert type should be X.509", cert.getType(), "X.509");
        }
        final String issuer = (cvc ? "CN=CAREF001,C=SE" : DnComponents.stringToBCDNString(testIssuerDn));
        assertEquals("Returned certificate contained unexpected issuer", issuer, CertTools.getIssuerDN(cert));
        final String subject = (cvc
                ? "CN=RESTCVC01,C=SE"
                : DnComponents.stringToBCDNString("C=EE,ST=Alabama,L=tallinn,O=naabrivalve,CN=hello123server6"));
        assertEquals("Returned certificate contained unexpected subject DN", subject, CertTools.getSubjectDN(cert));

        EndEntityInformation userData = endEntityAccessSession.findUser(INTERNAL_ADMIN_TOKEN, testUsername);
        assertEquals("Created user does not have expected email.", email, userData.getEmail());
    }

    @Test
    public void enrollPkcs10ExpectResponseFormatPKCS7() throws Exception {
        String responseFormat = "PKCS7";

        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(testCaName).
                certificateProfileName("ENDUSER").
                endEntityProfileName("EMPTY").
                username(testUsername).
                password("foo123").includeChain(false).responseFormat(responseFormat).
                certificateRequest(CSR_WITHOUT_HEADERS).build();

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
        final String responseFormatREST = (String) actualJsonObject.get("response_format");
        assertEquals("The response format is not PKCS7", responseFormat, responseFormatREST);
        final String responseCertificate = (String) actualJsonObject.get("certificate");
        assertNotNull(responseCertificate);
        //Verify certificate is a pkcs7
        String pkcs7CertificatePem = new String(Base64.decode(responseCertificate.getBytes()), StandardCharsets.UTF_8);
        assertTrue("The response is not a pkcs7", pkcs7CertificatePem.contains(CertTools.BEGIN_PKCS7));
        assertTrue("The response is not a pkcs7", pkcs7CertificatePem.contains(CertTools.END_PKCS7));
        //Varify certificate
        pkcs7CertificatePem = pkcs7CertificatePem.replaceFirst("^-----BEGIN PKCS7-----","");
        pkcs7CertificatePem = pkcs7CertificatePem.replaceFirst("-----END PKCS7-----$", "");
        byte[] certBytes = Base64.decode(pkcs7CertificatePem.getBytes());
        Certificate cert = CertTools.getCertfromByteArray(certBytes, Certificate.class);
        String responseSerialNo = (String) actualJsonObject.get("serial_number");
        assertEquals("", CertTools.getSerialNumber(cert), CertTools.getSerialNumberFromString(responseSerialNo));
    }

    @Test
    public void certificateRequestExpectCsrSubjectIgnoredWithoutHeaders() throws Exception {
        certificateRequestExpectCsrSubjectIgnored(false);
    }

    @Test
    public void certificateRequestExpectCsrSubjectIgnoredWithHeaders() throws Exception {
        certificateRequestExpectCsrSubjectIgnored(true);
    }

    private void certificateRequestExpectCsrSubjectIgnored(boolean withHeader) throws Exception {
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
                certificateRequest(withHeader? CSR_WITH_HEADERS: CSR_WITHOUT_HEADERS).build();
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
    public void testGetCertificateAboutToExpireSmoke() throws Exception {
        final Response actualResponse = newRequest("/v1/certificate/expire?days=1").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object certificatesToExpire = actualJsonObject.get("certificates_rest_response");
        assertNotNull(certificatesToExpire);
    }
    
    @Test
    public void testGetCertificateAboutToExpireDetailedSearch() throws Exception {
        
        final String issuerDN = "CN=CaSigningForVariedValidity";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false, 
                            X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo caInfo = (X509CAInfo) testX509Ca.getCAInfo();
        caInfo.setDoEnforceUniquePublicKeys(false);
        testX509Ca.setCAInfo(caInfo);
        caSession.addCA(INTERNAL_ADMIN_TOKEN, testX509Ca);
        
        final String profilePrefix = "CertProfileVariedValidity";
        // there is always a 10min in past offset
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setEncodedValidity("30m");
        int certificateProfile30mId = 
                certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "30m", certificateProfile);

        certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setEncodedValidity("5d");
        int certificateProfile5dId = 
                certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "5d", certificateProfile);

        certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setEncodedValidity("15d");
        certificateProfile.setAvailableCAs(Arrays.asList(issuerDN.hashCode()));
        int certificateProfile15dId = 
                certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "15d", certificateProfile);

        
        final String eeProfileName = "EeProfileVariedValidity";
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setDefaultCertificateProfile(certificateProfile30mId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(
                                    certificateProfile30mId, certificateProfile5dId, certificateProfile15dId));
        endEntityProfile.setAvailableCAs(Arrays.asList(issuerDN.hashCode()));
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(
                                INTERNAL_ADMIN_TOKEN, eeProfileName, endEntityProfile);        
        
        List<String> addedUserNames = new ArrayList<>();
        
        try {
            // there is no limit for offset or max results today
            int created30mCerts = 50;
            for (int i=0; i<50; i++) {
                String username = addAndEnrollEntity(issuerDN,  profilePrefix + "30m", certificateProfile30mId,
                                            eeProfileName, endEntityProfileId);
                if (username!=null) {
                    addedUserNames.add(username);
                } else {
                    created30mCerts--;
                }
            }
            
            int created5dCerts = 75;
            for (int i=0; i<75; i++) {
                String username = addAndEnrollEntity(issuerDN,  profilePrefix + "5d", certificateProfile5dId,
                                            eeProfileName, endEntityProfileId);
                if (username!=null) {
                    addedUserNames.add(username);
                } else {
                    created5dCerts--;
                }
            }
            
            int created15dCerts = 60;
            for (int i=0; i<60; i++) {
                String username = addAndEnrollEntity(issuerDN,  profilePrefix + "15d", certificateProfile15dId,
                                            eeProfileName, endEntityProfileId);
                if (username!=null) {
                    addedUserNames.add(username);
                } else {
                    created15dCerts--;
                }
            }
            
            // test vectors
            // 1d offset: 0, 10
            searchToBeExpiredCerts(1, 0, 0, created30mCerts);
            searchToBeExpiredCerts(1, 10, 0, created30mCerts - 10);
            // 6d offset: 0, 10
            searchToBeExpiredCerts(6, 0, 0, created30mCerts + created5dCerts);
            searchToBeExpiredCerts(6, 10, 0, created30mCerts + created5dCerts - 10);
            // 16d offset: 0, 10
            searchToBeExpiredCerts(16, 0, 0, created30mCerts + created5dCerts + created15dCerts);
            searchToBeExpiredCerts(16, 10, 0, created30mCerts + created5dCerts + created15dCerts - 10);
            
            // 1d offset: 10, max: 10,50  offset: 40, max: 10,50
            searchToBeExpiredCerts(1, 10, 10, created30mCerts - 10);
            searchToBeExpiredCerts(1, 10, 50, created30mCerts - 10, false);
            searchToBeExpiredCerts(1, 40, 10, created30mCerts - 40, false);
            searchToBeExpiredCerts(1, 40, 50, created30mCerts - 40, false);
            // 6d
            searchToBeExpiredCerts(6, 10, 10, created30mCerts + created5dCerts - 10);
            searchToBeExpiredCerts(6, 10, 50, created30mCerts + created5dCerts - 10);
            searchToBeExpiredCerts(6, 40, 10, created30mCerts + created5dCerts - 40);
            searchToBeExpiredCerts(6, 40, 50, created30mCerts + created5dCerts - 40);
            // 16d
            searchToBeExpiredCerts(16, 10, 10, created30mCerts + created5dCerts + created15dCerts - 10);
            searchToBeExpiredCerts(16, 10, 50, created30mCerts + created5dCerts + created15dCerts - 10);
            searchToBeExpiredCerts(16, 40, 10, created30mCerts + created5dCerts + created15dCerts - 40);
            searchToBeExpiredCerts(16, 40, 50, created30mCerts + created5dCerts + created15dCerts - 40);
            
            // negative integers are possible as input, please be gentle
            
        } catch (Exception e) {
            log.error("Exception while testing expired certificate search: ", e);
            fail("Exception while testing expired certificate search");
        } finally {
        
            for (String user: addedUserNames) {
                endEntityManagementSession.revokeAndDeleteUser(INTERNAL_ADMIN_TOKEN, user, 0);
                internalCertificateStoreSession.removeCertificatesByUsername(user);
            }
            
            endEntityProfileSession.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, eeProfileName);
            certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "30m");
            certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "5d");
            certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, profilePrefix + "15d");
            caSession.removeCA(INTERNAL_ADMIN_TOKEN, issuerDN.hashCode());
        }
        
    }
    
    private void searchToBeExpiredCerts(int days, int offset, int maxResult, 
            int minimumResultsExpected) throws Exception {
        searchToBeExpiredCerts(days, offset, maxResult, minimumResultsExpected, true);
    }
    
    private void searchToBeExpiredCerts(int days, int offset, int maxResult, 
                                                int minimumResultsExpected, boolean expectedMoreResults) throws Exception {
        
        String url = "/v1/certificate/expire?days=" + days;
        if (offset!=0) {
            url += "&offset=" + offset;
        }
        if (maxResult==0) {
            maxResult = 25;
        }
        url += "&maxNumberOfResults=" + maxResult;
        int expectedEntries = maxResult;
        
        log.error("searchToBeExpiredCerts url: " + url);
        final Response actualResponse = newRequest(url).request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        assertJsonContentType(actualResponse);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject certificatesToExpire = (JSONObject) actualJsonObject.get("certificates_rest_response");
        assertNotNull(certificatesToExpire);
        
        final JSONObject pagination = (JSONObject) actualJsonObject.get("pagination_rest_response_component");
        assertNotNull(pagination);
        
        assertTrue(pagination.containsKey("more_results"));
        assertTrue(pagination.containsKey("number_of_results"));
        assertTrue(pagination.containsKey("next_offset"));
        
        assertTrue("number_of_results is lower than expected", 
                (long) pagination.get("number_of_results") >= minimumResultsExpected - expectedEntries);
        
        assertTrue(certificatesToExpire.containsKey("certificates"));
        JSONArray certificates = (JSONArray) certificatesToExpire.get("certificates");
        if (expectedMoreResults) {
            assertEquals("certificates has mismatched number of entries", certificates.size(), expectedEntries);
        } else {
            assertFalse("certificates has mismatched number of entries with no next page", certificates.isEmpty());
        }
        
        return;
    }
    
    @Test
    public void testCreateCertificateNonExistingCa() throws Exception {
        
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10CertificationRequest = CertTools.genPKCS10CertificationRequest(
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                DnComponents.stringToBcX500Name("CN=DUMMY_USER"), 
                keys.getPublic(), null, keys.getPrivate(), null);

        String caName = "testCreateCertificateNonExistingCa_DUMMY_CA";
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder()
                .certificateAuthorityName(caName)
                .username("DUMMY_USER")
                .password("foo123")
                .certificateProfileName("DUMMY_CP")
                .endEntityProfileName("DUMMY_EEP")
                .certificateRequest(CertTools.buildCsr(pkcs10CertificationRequest)).build();
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(pkcs10req);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);

        // Send request
        final Response actualResponse = newRequest("/v1/certificate/certificaterequest").request().post(requestEntity);
        String responseBody = actualResponse.readEntity(String.class);
        assertTrue(responseBody.contains("CA with name " + caName + " doesn't exist."));
    }
    
    private String addAndEnrollEntity(String caDn, String certProfileName, int certProfileId,
                                                            String eeProfileName, int eeProfileId) {
        String userName = "expireSearchTest" + RANDOM.nextLong();
        
        try {
            EndEntityInformation userdata = new EndEntityInformation(
                    userName, "CN=" + userName, caDn.hashCode(), null,
                    null, new EndEntityType(EndEntityTypes.ENDUSER), 
                    eeProfileId, certProfileId,
                    SecConst.TOKEN_SOFT_BROWSERGEN, new ExtendedInformation());
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
            userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
            endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, userdata, false);
            
            final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            PKCS10CertificationRequest pkcs10CertificationRequest = CertTools.genPKCS10CertificationRequest(
                    AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                    DnComponents.stringToBcX500Name("CN=" + userName), 
                    keys.getPublic(), null, keys.getPrivate(), null);

            // Create CSR REST request
            EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder()
                    .certificateAuthorityName(caDn.substring(3))
                    .username(userName)
                    .password("foo123")
                    .certificateProfileName(certProfileName)
                    .endEntityProfileName(eeProfileName)
                    .certificateRequest(CertTools.buildCsr(pkcs10CertificationRequest)).build();
            // Construct POST  request
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(pkcs10req);
            final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
    
            // Send request
            final Response actualResponse = newRequest("/v1/certificate/certificaterequest").request().post(requestEntity);
            if (actualResponse.getStatus()!=201) {
                return null;
            }
        } catch (Exception e) {
            log.error("Exception while adding: " + userName, e);
            return null;
        }
        
        return userName;
    }
    
    @Test
    public void enrollPkcs10WithUnidFnr() throws Exception {

        final String username = "enrollPkcs10WithUnidFnr";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN=" + username;

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
                DnComponents.stringToBcX500Name(subjectDn), keys.getPublic(), null, keys.getPrivate(), null);
        String unidFnrCsr = CertTools.buildCsr(pkcs10CertificationRequest);

        // Create CSR REST request
        EnrollPkcs10CertificateRequest pkcs10req = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(testX509CaInfo.getName()).
                certificateProfileName(profileName).
                endEntityProfileName(profileName).
                username(username).
                password(password). responseFormat("DER").
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
            byte[] certBytes = Base64.decode(base64cert.getBytes());
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
            Approval approval = new Approval("REST System Test Approval", AccumulativeApprovalProfile.FIXED_STEP_ID,
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
     *
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
     * Enables "Allow Invalidity Date" for test CA
     */
    private void enableInvalidityDate() throws Exception {
        X509CAInfo caInfo = (X509CAInfo) x509TestCa.getCAInfo();
        caInfo.setAllowInvalidityDate(true);
        caAdminSession.editCA(INTERNAL_ADMIN_TOKEN, caInfo);
    }

    /**
     * Disables "Allow Invalidity Date" for test CA
     */
    private void disableInvalidityDate() throws Exception {
        X509CAInfo caInfo = (X509CAInfo) x509TestCa.getCAInfo();
        caInfo.setAllowInvalidityDate(false);
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
        return new CertificateRestResourceSystemTestUtil()
                .createTestEndEntity(TestEndEntityParamHolder.newBuilder()
                        .withX509TestCa(x509TestCa)
                        .withTestUsername(testUsername)
                        .withTestCertProfileName(testCertProfileName)
                        .withTestEeProfileName(testEeProfileName)
                        .withInternalAdminToken(INTERNAL_ADMIN_TOKEN)
                        .withCertificateProfileSession(certificateProfileSession)
                        .withEndEntityManagementSession(endEntityManagementSession)
                        .withEndEntityProfileSessionRemote(endEntityProfileSessionRemote)
                        .build());
    }
    
    /**
     * Creates a keystore with a certificate for the test End Entity
     */
    private KeyStore createKeystore(final String keySpec, final String keyAlg) throws Exception {
        final byte[] keyStoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(
                INTERNAL_ADMIN_TOKEN,
                testUsername,
                "foo123",
                x509TestCa.getCAId(),
                keySpec,
                keyAlg,
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
        final KeyStore keyStore = createKeystore("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        return CertTools.getSerialNumberAsString(keyStore.getCertificate(testUsername));
    }

    /**
     * Creates a CRL for the test CA
     *
     * @param delta true for delta CRL, false for base CRL
     */
    private X509CRL createCrl(final boolean delta) throws Exception {
        final String orderedIssuerDn = DnComponents.stringToBCDNString(testIssuerDn);
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
        final String orderedIssuerDn = DnComponents.stringToBCDNString(testIssuerDn);
        final String deltaCrlParameter = (delta) ? "?deltacrl=true" : "";

        // get the created CRL
        final Response latestCRLResponse = newRequest("/v1/ca/" + orderedIssuerDn + "/getLatestCrl" + deltaCrlParameter).request().get();
        assertEquals("Failed to retrieve latest CRL", 200, latestCRLResponse.getStatus());

        final JSONObject latestCRLResponseAsJSON = (JSONObject) jsonParser.parse(latestCRLResponse.readEntity(String.class));
        final Object latestCRL = latestCRLResponseAsJSON.get("crl");
        assertNotNull("Response does not contain a CRL", latestCRL);

        return CertTools.getCRLfromByteArray(Base64.decode(latestCRL.toString().getBytes()));
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
        final EntityPart fileEP = EntityPart.withName("crlFile").fileName(CRL_FILENAME).content(new File(CRL_FILENAME)).build();
        final EntityPart crlPartitionIndexEP = EntityPart.withName("crlPartitionIndex").content(0, Integer.class).build();
        final List<EntityPart> entityParts = Arrays.asList(fileEP, crlPartitionIndexEP);

        final Entity requestEntity = Entity.entity(new GenericEntity<>(entityParts){}, MediaType.MULTIPART_FORM_DATA);

        final WebTarget crlImportRequest = newRequest("/v1/ca/" + DnComponents.stringToBCDNString(testIssuerDn) + "/importcrl");
        final Response crlImportResponse = crlImportRequest.request().post(requestEntity);

        assertEquals("CRL import failed", Response.Status.OK.getStatusCode(), crlImportResponse.getStatus());
        Files.deleteIfExists(Paths.get(CRL_FILENAME));
    }

    /**
     * Generates a new CRL containing a certificate with the desired revocation reason and deletes all CRLs of the test CA.
     *
     * @param fingerprint             of certificate whose revocation reson should be changed
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
