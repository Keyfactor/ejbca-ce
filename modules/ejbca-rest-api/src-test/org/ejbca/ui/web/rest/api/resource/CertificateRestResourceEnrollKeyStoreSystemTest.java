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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.rest.api.resource.util.CertificateRestResourceSystemTestUtil;
import org.ejbca.ui.web.rest.api.resource.util.TestEndEntityParamHolder;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class CertificateRestResourceEnrollKeyStoreSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CertificateRestResourceEnrollKeyStoreSystemTest.class);
    
    private static final JSONParser jsonParser = new JSONParser();
    
    private static final String TEST_USER_PREFIX = "EnrollKeyStoreSystemTestUser";
    private static final String TEST_CA_NAME = "CaSigningRestEnrollKeyStore";
    private static final String TEST_CA_DN = "CN=" + TEST_CA_NAME;
    private static final String TEST_CERT_PROFILE_NAME = "CertProfileRestEnrollKeyStore";
    private static final String TEST_CERT_PROFILE_RSA_ONLY_NAME = "CertProfileRsaOnlyRestEnrollKeyStore";
    private static final String TEST_EE_PROFILE_NAME = "EeProfileRestEnrollKeyStore";
    private static final String TEST_EE_PROFILE_KEY_RECOVERY_NAME = "EeProfileKeyRecovRestEnrollKeyStore";
    
    private static X509CA testX509Ca;
    
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final TestRaMasterApiProxySessionRemote raMasterApiProxyBean = EjbRemoteHelper.INSTANCE
                                    .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static final List<String> addedUserNames = new ArrayList<>();
    private static final Random RANDOM = new Random();
    
    private static boolean useKeyRecoveryBkup;
    
    @Rule
    public final TestWatcher traceLogMethodsRule = new TraceLogMethodsTestWatcher(log);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        RestResourceSystemTestBase.beforeClass();
        
        useKeyRecoveryBkup = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(
                GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
        GlobalConfiguration globalConfiguration = (GlobalConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, globalConfiguration);
        
        // only RSA CA is being tested, key recovery with ECDSA CA should be tested independently
        testX509Ca = CaTestUtils.createTestX509CA(TEST_CA_DN, null, false, 
                            X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo caInfo = (X509CAInfo) testX509Ca.getCAInfo();
        caInfo.setDoEnforceUniquePublicKeys(false);
        testX509Ca.setCAInfo(caInfo);
        caSession.addCA(INTERNAL_ADMIN_TOKEN, testX509Ca);
        
        // there is always a 10min in past offset
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setEncodedValidity("30m");
        certificateProfile.setAvailableBitLengthsAsList(Arrays.asList(2048, 256));
        int certificateProfileId = 
                certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERT_PROFILE_NAME, certificateProfile);
        
        certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setEncodedValidity("30m");
        certificateProfile.setAvailableKeyAlgorithmsAsList(Arrays.asList(AlgorithmConstants.KEYALGORITHM_RSA));
        certificateProfile.setAvailableBitLengthsAsList(Arrays.asList(2048, 256));
        int certificateProfileRsaOnlyId = 
                certificateProfileSession.addCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERT_PROFILE_RSA_ONLY_NAME, certificateProfile);
        
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId, certificateProfileRsaOnlyId));
        endEntityProfile.setAvailableCAs(Arrays.asList(TEST_CA_DN.hashCode()));
        endEntityProfileSession.addEndEntityProfile(
                                INTERNAL_ADMIN_TOKEN, TEST_EE_PROFILE_NAME, endEntityProfile);   
        
        endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setKeyRecoverableUsed(true);
        endEntityProfile.setKeyRecoverableDefault(true);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId, certificateProfileRsaOnlyId));
        endEntityProfile.setAvailableCAs(Arrays.asList(TEST_CA_DN.hashCode()));
        endEntityProfileSession.addEndEntityProfile(
                                INTERNAL_ADMIN_TOKEN, TEST_EE_PROFILE_KEY_RECOVERY_NAME, endEntityProfile);   
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
        GlobalConfiguration globalConfiguration = (GlobalConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableKeyRecovery(useKeyRecoveryBkup);
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, globalConfiguration);
        
        for (String user: addedUserNames) {
            endEntityManagementSession.revokeAndDeleteUser(INTERNAL_ADMIN_TOKEN, user, 0);
            internalCertificateStoreSession.removeCertificatesByUsername(user);
        }
        
        endEntityProfileSession.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
        endEntityProfileSession.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, TEST_EE_PROFILE_NAME);
        certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERT_PROFILE_RSA_ONLY_NAME);
        certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, TEST_CERT_PROFILE_NAME);
        caSession.removeCA(INTERNAL_ADMIN_TOKEN, TEST_CA_DN.hashCode());
    }
    
    // enroll RSA key x 3 types of keystore
    @Test
    public void enrollRsaPkcs12() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollRsaJks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollRsaBcfks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    // enroll ECDSA key
    @Test
    public void enrollEcdsaPkcs12() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollEcdsaJks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollEcdsaBcfks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_ECDSA, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }

    // enroll ML-DSA-44 key x 3 types of keystore
    @Test
    public void enrollMLDSA44Pkcs12() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollMLDSA44Jks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollMLDSA44Bcfks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_MLDSA44, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    // enroll FALCON-512 key x 3 types of keystore
    @Test
    public void enrollFalcon512Pkcs12() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_P12, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollFalcon512Jks() {
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_NAME);
        enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_JKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    @Test
    public void enrollFalcon512Bcfks() {
        // TODO: ECA-12721 Fix. Fails at
        // com.keyfactor.util.keys.KeyTools.createBcfks
        // Caused by: java.lang.IllegalStateException: java.security.KeyStoreException: BCFKS not found 
        // java.security.NoSuchAlgorithmException: no such algorithm: BCFKS for provider BCPQC
        // enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_NAME);
        // TODO: ECA-12721 Fix. See above. 
        // enrollKeyStore(AlgorithmConstants.KEYALGORITHM_FALCON512, SecConst.TOKEN_SOFT_BCFKS, TEST_EE_PROFILE_KEY_RECOVERY_NAME);
    }
    
    private void enrollKeyStore(String keyAlgorithm, int tokenType, String eeProfileName) {
        
        String keySpec = keyAlgorithm.equals(AlgorithmConstants.KEYALGORITHM_RSA) ? "2048" : "secp256r1";
        String userName = createUser(eeProfileName, TEST_CERT_PROFILE_NAME, tokenType, keyAlgorithm, 
                keySpec);
        
        String responseBody = enrollKeyStoreRestCall(userName, 
                CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD, keyAlgorithm, keySpec);
        
        // TODO: process response body
        log.error(responseBody);
        String certificateSerialNo = null;
        try {
            final JSONObject keyStoreEnrollResponse = (JSONObject) jsonParser.parse(responseBody);
            
            assertTrue(keyStoreEnrollResponse.containsKey("certificate"));
            assertTrue(keyStoreEnrollResponse.containsKey("serial_number"));
            assertTrue(keyStoreEnrollResponse.containsKey("response_format"));
            assertTrue(keyStoreEnrollResponse.containsKey("certificate_chain"));
            
            certificateSerialNo = (String) keyStoreEnrollResponse.get("serial_number");
        } catch (ParseException e1) {
            log.error(e1);
            fail("failed to parse keystore enroll response");
        }
        
        // TODO: process key recovery
        if (eeProfileName.equals(TEST_EE_PROFILE_KEY_RECOVERY_NAME)) {
            byte[] keyStoreRecovered = null;
            try {
                try {
                    endEntityManagementSession.setPassword(INTERNAL_ADMIN_TOKEN, userName, 
                                            CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD);
                } catch (NoSuchEndEntityException | EndEntityProfileValidationException e) {
                    // TODO Auto-generated catch block
                    throw new IllegalStateException(e);
                }
                keyStoreRecovered = raMasterApiProxyBean.keyRecoverEnrollWS(INTERNAL_ADMIN_TOKEN, userName, certificateSerialNo, 
                        TEST_CA_DN, CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD, null);
            } catch (CADoesntExistsException | AuthorizationDeniedException | EjbcaException | WaitingForApprovalException e) {
                log.error("Failed to recover key: ", e);
                fail("Failed to recover key: key algo: " + keyAlgorithm + ", tokenType: " + tokenType);
            }
            
            assertNotNull("Failed to recover key(keyStore null): key algo: " + keyAlgorithm + 
                    ", tokenType: " + tokenType, keyStoreRecovered);
            assertTrue("Failed to recover key(keyStore empty): key algo: " + keyAlgorithm + 
                    ", tokenType: " + tokenType, keyStoreRecovered.length!=0);

        }
    }
    
    private String createUser(String eeProfileName, String certProfileName, int tokenType, String keyalgorithm, String keySpec) {
        String userName = TEST_USER_PREFIX + RANDOM.nextLong();
        
        try {
           new CertificateRestResourceSystemTestUtil()
                    .createTestEndEntity(TestEndEntityParamHolder.newBuilder()
                            .withX509TestCa(testX509Ca)
                            .withTestUsername(userName)
                            .withTestCertProfileName(certProfileName)
                            .withTestEeProfileName(eeProfileName)
                            .withInternalAdminToken(INTERNAL_ADMIN_TOKEN)
                            .withCertificateProfileSession(certificateProfileSession)
                            .withEndEntityManagementSession(endEntityManagementSession)
                            .withEndEntityProfileSessionRemote(endEntityProfileSession)
                            .withTokenType(tokenType)
                            .withKeyAlgo(keyalgorithm)
                            .withKeySpec(keySpec)
                            .withKeyRecoverable(eeProfileName.equals(TEST_EE_PROFILE_KEY_RECOVERY_NAME))
                            .build());
        } catch (Exception e) {
            log.error("Failed to create user:", e);
            fail("Failed to create user with EEP: " + eeProfileName + ", CP: " +  certProfileName + ", token: " + tokenType);
        }
        
        addedUserNames.add(userName);
        return userName;
    }
    
    private String enrollKeyStoreRestCall(String username, String password, String keyAlgo, String keySpec) {
        return enrollKeyStoreRestCall(username, password, keyAlgo, keySpec, false);
    }
    
    private String enrollKeyStoreRestCall(String username, String password, String keyAlgo, String keySpec, boolean expectError) {
        
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", username);
        requestBody.put("password", password);
        requestBody.put("key_alg", keyAlgo);
        requestBody.put("key_spec", keySpec);
        
        String actualJsonString = null;
        try {
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBodyStr = objectMapper.writeValueAsString(requestBody);
            final Entity<String> requestEntity = Entity.entity(requestBodyStr, MediaType.APPLICATION_JSON);
            // Send request
            final Response actualResponse = newRequest("/v1/certificate/enrollkeystore").request().post(requestEntity);
            actualJsonString = actualResponse.readEntity(String.class);
            // Verify response
            assertJsonContentType(actualResponse);
            if (expectError) {
                assertTrue("Unexpected status code for bad keystore enroll request", actualResponse.getStatus() > 399);
            } else {
                assertEquals("Unexpected status code for good keystore enroll request", actualResponse.getStatus(), 201);
            }
        } catch (Exception e) {
            log.error("Failed to enroll keystore:", e);
            log.error("Failed to enroll keystore: request: " + requestBody + ", response: " +  actualJsonString);
            fail("Failed to enroll keystore: " + requestBody);
        }
        
        return actualJsonString;
    }
        
    // negative: empty user name, password, CA, non-existent EE, wrong password, not allowed bit length, not allowed algo
    @Test
    public void badEnrollEmptyUsername() {
        String responseBody = enrollKeyStoreRestCall("", "foo123", "RSA", "2048", true);
        log.error("badEnrollEmptyUsername" + responseBody);
    }

    @Test
    public void badEnrollEmptyPassword() {
        String responseBody = enrollKeyStoreRestCall("user", "", "RSA", "2048", true);
        log.error("badEnrollEmptyPassword" + responseBody);
    }

    @Test
    public void badEnrollEmptyAlgo() {
        String responseBody = enrollKeyStoreRestCall("user", "foo123", "", "256", true);
        log.error("badEnrollEmptyAlgo" + responseBody);
    }

    @Test
    public void badEnrollEmptySpec() {
        String responseBody = enrollKeyStoreRestCall("user", "foo123", "RSA", "", true);
        log.error("badEnrollEmptySpec" + responseBody);
    }
    
    @Test
    public void badEnrollNonExistentEndEntity() {
        String responseBody = enrollKeyStoreRestCall("user" + RANDOM.nextLong(), "foo123", "RSA", "2048", true);
        log.error("badEnrollNonExistentEndEntity" + responseBody);
    }

    @Test
    public void badEnrollNotAllowedBitLength() {
        String userName = createUser(TEST_EE_PROFILE_NAME, TEST_CERT_PROFILE_RSA_ONLY_NAME, 
                SecConst.TOKEN_SOFT_P12, AlgorithmConstants.KEYALGORITHM_RSA, 
                "2048");
        
        String responseBody = enrollKeyStoreRestCall(userName, 
                CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD, 
                AlgorithmConstants.KEYALGORITHM_RSA, "4096");
        log.error("badEnrollNotAllowedBitLength" + responseBody);
        
        try {
            final JSONObject keyStoreEnrollResponse = (JSONObject) jsonParser.parse(responseBody);
            X509Certificate enrolledCert = CertTools.extractEndEntityCertificateFromKeyStore(
                    Base64.decode(((String) keyStoreEnrollResponse.get("certificate")).getBytes()), 
                    SecConst.getKeyStoreTypeAsString(SecConst.TOKEN_SOFT_P12), 
                    CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD).get(0);
            
            assertEquals(enrolledCert.getPublicKey().getAlgorithm(), "RSA"); 
            assertEquals(KeyTools.getKeyLength(enrolledCert.getPublicKey()), 2048);
            
        } catch (Exception e1) {
            log.error(e1);
            fail("failed to parse keystore enroll response");
        }
    }
    
    @Test
    public void badEnrollNotAllowedAlgorithm() {
        String userName = createUser(TEST_EE_PROFILE_NAME, TEST_CERT_PROFILE_RSA_ONLY_NAME, 
                SecConst.TOKEN_SOFT_P12, AlgorithmConstants.KEYALGORITHM_RSA, 
                "2048");
        
        String responseBody = enrollKeyStoreRestCall(userName, 
                CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD, 
                AlgorithmConstants.KEYALGORITHM_ECDSA, "secp256r1");
        log.error("badEnrollNotAllowedAlgorithm" + responseBody);
        
        try {
            final JSONObject keyStoreEnrollResponse = (JSONObject) jsonParser.parse(responseBody);
            X509Certificate enrolledCert = CertTools.extractEndEntityCertificateFromKeyStore(
                    Base64.decode(((String) keyStoreEnrollResponse.get("certificate")).getBytes()), 
                    SecConst.getKeyStoreTypeAsString(SecConst.TOKEN_SOFT_P12),
                    CertificateRestResourceSystemTestUtil.DEFAULT_PASSWORD).get(0);
            
            assertEquals(enrolledCert.getPublicKey().getAlgorithm(), "RSA"); 
            
        } catch (Exception e1) {
            log.error(e1);
            fail("failed to parse keystore enroll response");
        }
    }
}
