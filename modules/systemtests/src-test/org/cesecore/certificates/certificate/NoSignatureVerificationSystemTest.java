/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.util.Arrays;

import com.keyfactor.util.keys.token.KeyGenParams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Simplified System test for Use Signature Verification setting in Certificate Profiles.
 * Verifies that the setting is correctly persisted through management sessions
 * and correctly affects the issuance process in X509CAImpl.
 */
public class NoSignatureVerificationSystemTest extends RoleUsingTestCase {

    final private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    final private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    final private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    final private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    final private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        setUpAuthTokenAndRole(null, "NoSigVerSysTest", Arrays.asList(
                StandardRules.CERTIFICATEPROFILEEDIT.resource(),
                StandardRules.CERTIFICATEPROFILEVIEW.resource(),
                StandardRules.CAADD.resource(),
                StandardRules.CAEDIT.resource(),
                StandardRules.CAREMOVE.resource(),
                StandardRules.CAACCESSBASE.resource(),
                StandardRules.CREATECERT.resource(),
                CryptoTokenRules.BASE.resource(),
                StandardRules.ROLE_ROOT.resource()
                ), null);
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    @Test
    public void testSettingPersistence() throws Exception {
        final String profileName = "NoSigVerPersistenceProfile";
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        
        // 1. Verify default value
        assertTrue("Default value should be true (verification enabled)", profile.getUseSignatureVerification());
        
        // 2. Change value and save
        profile.setUseSignatureVerification(false);
        final int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, profileName, profile);
        try {
            // 3. Retrieve and verify
            final CertificateProfile retrievedProfile = certProfileSession.getCertificateProfile(cpId);
            assertNotNull("Profile should be retrieved", retrievedProfile);
			assertFalse("Setting should be persisted as false (verification disabled)", retrievedProfile.getUseSignatureVerification());
            
            // 4. Change back and save
            retrievedProfile.setUseSignatureVerification(true);
            certProfileSession.changeCertificateProfile(roleMgmgToken, profileName, retrievedProfile);
            
            // 5. Retrieve and verify again
            final CertificateProfile retrievedUpdatedProfile = certProfileSession.getCertificateProfile(cpId);
			assertTrue("Setting should be persisted as true", retrievedUpdatedProfile.getUseSignatureVerification());
            
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, profileName);
        }
    }

    @Test
    public void testSignatureVerificationEffect() throws Exception {
        final String rootCaName = "NoSigVerTestRootCA";
        final String subCaName = "NoSigVerTestSubCA";
        final String profileName = "NoSigVerTestProfile";
        final String userName = "NoSigVerTestUser";
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final String keySpec = "1024";

        try {
            // 1. Setup Root CA
            final X509CA rootCa = CaTestUtils.createX509Ca(roleMgmgToken, "NoSigVerRootToken", rootCaName, "CN="+rootCaName, CAConstants.CA_ACTIVE);
            final int rootCaId = rootCa.getCAId();

            // 2. Setup Sub CA
            final CAInfo subCaInfoVO = CaTestUtils.createTestX509SubCAGenKeys(roleMgmgToken, "CN="+subCaName, null, rootCaId, keySpec, keySpec, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            final int subCaId = subCaInfoVO.getCAId();
            final int subCryptoTokenId = subCaInfoVO.getCAToken().getCryptoTokenId();

            // 3. Setup Certificate Profile
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            final int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, profileName, cp);

            // 4. Setup End Entity for Sub CA
            final EndEntityInformation user = new EndEntityInformation(userName, "CN=" + userName, subCaId, null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            final KeyPair userKeyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
            final JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + userName), userKeyPair.getPublic());
            final PKCS10CertificationRequest p10 = p10Builder.build(new JcaContentSignerBuilder(algName).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(userKeyPair.getPrivate()));
            final PKCS10RequestMessage req = new PKCS10RequestMessage(p10.getEncoded());
            
            // 5. Simulate Sub CA key mismatch: Generate new key for Sub CA signing alias, but don't update Sub CA cert.
            cryptoTokenManagementSession.removeKeyPair(roleMgmgToken, subCryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS);
            cryptoTokenManagementSession.createKeyPair(roleMgmgToken, subCryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, KeyGenParams.builder("RSA2048").build());
            
            // Case A: Verification Enabled (default in the profile)
            try {
                certificateCreateSession.createCertificate(roleMgmgToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
                fail("Issuance should have failed because Sub CA key mismatch and signature verification is enabled");
            } catch (CertificateCreateException e) {
                assertTrue("Error message should mention CA certificate mismatch. Was: " + e.getMessage(), 
                        e.getMessage() != null && e.getMessage().contains("Public key in the CA certificate does not match"));
            }
            
            // Case B: Verification Disabled
            cp.setUseSignatureVerification(false);
            certProfileSession.changeCertificateProfile(roleMgmgToken, profileName, cp);
            
            final X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Issuance should have succeeded with signature verification disabled", resp.getCertificate());
            
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, profileName);
            
            final CAInfo subCaInfo = caSession.getCAInfo(roleMgmgToken, subCaName);
            CaTestUtils.removeCa(roleMgmgToken, subCaInfo);
            
            final CAInfo rootCaInfo = caSession.getCAInfo(roleMgmgToken, rootCaName);
            CaTestUtils.removeCa(roleMgmgToken, rootCaInfo);
        }
    }
}
