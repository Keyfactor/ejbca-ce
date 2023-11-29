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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

public class CertificateRestResourceEnrollKeyStoreSystemTest extends RestResourceSystemTestBase {
    
    private static final Logger log = Logger.getLogger(CertificateRestResourceEnrollKeyStoreSystemTest.class);
    
    private static final JSONParser jsonParser = new JSONParser();
    
    private static final String TEST_USER_PREFIX = "EnrollKeyStoreSystemTestUser";
    private static final String TEST_CA_DN = "CN=CaSigningRestEnrollKeyStore";
    private static final String TEST_CERT_PROFILE_NAME = "CertProfileRestEnrollKeyStore";
    private static final String TEST_CERT_PROFILE_RSA_ONLY_NAME = "CertProfileRsaOnlyRestEnrollKeyStore";
    private static final String TEST_EE_PROFILE_NAME = "EeProfileRestEnrollKeyStore";
    private static final String TEST_EE_PROFILE_KEY_RECOVERY_NAME = "EeProfileKeyRecovRestEnrollKeyStore";
    
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private static final List<String> addedUserNames = new ArrayList<>();
    private static final Random RANDOM = new Random();
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
        
        // only RSA CA is being tested, key recovery with ECDSA CA should be tested independently
        X509CA testX509Ca = CaTestUtils.createTestX509CA(TEST_CA_DN, null, false, 
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

    private void enrollKeyStore(String keyalgorithm, int tokenType, String eeProfileName) {
        
    }
    
    private String createUser(String eeProfileName, String certProfileName, int tokenType) {
        String userName = TEST_USER_PREFIX + RANDOM.nextLong();
        
        
        return userName;
    }
    
    private String enrollKeyStoreRestCall(String username, String password, String keyAlgo, String keySpec) throws Exception {
        
        Map<String, String> requestBody = new HashMap<>();
        
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBodyStr = objectMapper.writeValueAsString(requestBody);
        final Entity<String> requestEntity = Entity.entity(requestBodyStr, MediaType.APPLICATION_JSON);
        // Send request
        final Response actualResponse = newRequest("/v1/certificate/enrollkeystore").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);
        
        return actualJsonString;
            
    }
        
    // negative: empty user name, password, CA, non-existent EE, wrong password, not allowed bit length, not allowed algo
    // PEM not allowed
    
    // with and without key recovery

}
