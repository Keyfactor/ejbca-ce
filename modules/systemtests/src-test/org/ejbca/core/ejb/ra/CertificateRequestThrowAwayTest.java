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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistoryProxySessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * Test the combined function for editing and requesting a keystore/certificate in a single transaction.
 * 
 * These tests will verify that the CA settings - useCertReqHistory (Store copy of UserData at the time of certificate issuance.) - useUserStorage
 * (Store current UserData.) - useCertificateStorage (Store issued certificates and related information.) works as intended.
 * 
 * Certificate issuance should work with any combination of the settings from CMP in RA mode and EJBCA WS. The CMP/WS entry points in will be tested,
 * but at the used EJB entry points: - (Local)CertificateRequestSessionRemote.processCertReq(AuthenticationToken, EndEntityInformation, String, int,
 * String, int) - (Local)CertificateRequestSessionRemote.processCertReq(AuthenticationToken, EndEntityInformation, RequestMessage, Class)
 * 
 * Since CrmfRequestMessages are a bit more complicated to create, the much simpler PKCS10 Request messages will be used.
 * 
 * Test methods are assumed to run in sequential order, to save CA generation and profile setup time.
 * 
 * @version $Id$
 */
public class CertificateRequestThrowAwayTest {

    private static final Logger LOG = Logger.getLogger(CertificateRequestThrowAwayTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CertificateRequestThrowAwayTest"));
    private static final Random random = new SecureRandom();

    private static final String TESTCA_NAME = "ThrowAwayTestCA";

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private CertificateRequestSessionRemote certificateRequestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateRequestSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertReqHistoryProxySessionRemote certReqHistoryProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);



    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @BeforeClass
    public static void setupBeforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() throws Exception {
        CaTestCase.createTestCA(TESTCA_NAME);
    }
    
    @Test
    public void testCAConfigurationsWithIRequestMessage() throws Exception {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setUseCertificateStorage(true);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TESTCA_NAME, profile);
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setAvailableCAs(Arrays.asList(CaTestCase.getTestCAId(TESTCA_NAME)));
        endEntityProfileSession.addEndEntityProfile(admin, TESTCA_NAME, endEntityProfile);
        try {
            assertCAConfig(false, true, true);
            // Run through all possible configurations of what to store in the database
            for (int i = 0; i <= 7; i++) {
                generateCertificatePkcs10(certificateProfileId, profile, (i & 1) > 0, (i & 2) > 0, (i & 4) > 0, false);
            }
        } finally {
            certificateProfileSession.removeCertificateProfile(admin, TESTCA_NAME);
            endEntityProfileSession.removeEndEntityProfile(admin, TESTCA_NAME);
        }
    }

    @Test
    public void testCAConfigurationsWithStringRequest() throws Exception {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setUseCertificateStorage(true);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TESTCA_NAME, profile);
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setAvailableCAs(Arrays.asList(CaTestCase.getTestCAId(TESTCA_NAME)));
        endEntityProfileSession.addEndEntityProfile(admin, TESTCA_NAME, endEntityProfile);
        try {
            assertCAConfig(false, true, true);
            // Run through all possible configurations of what to store in the database
            for (int i = 0; i <= 7; i++) {
                generateCertificatePkcs10(certificateProfileId, profile, (i & 1) > 0, (i & 2) > 0, (i & 4) > 0, true);
            }
        } finally {
            certificateProfileSession.removeCertificateProfile(admin, TESTCA_NAME);
            endEntityProfileSession.removeEndEntityProfile(admin, TESTCA_NAME);
        }
    }

    @Test
    public void testCertificateProfileConfiguration() throws Exception {
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setUseCertificateStorage(false);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TESTCA_NAME, profile);
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfile.setAvailableCAs(Arrays.asList(CaTestCase.getTestCAId(TESTCA_NAME)));
        endEntityProfileSession.addEndEntityProfile(admin, TESTCA_NAME, endEntityProfile);
        try {
            assertCAConfig(false, true, true);
            generateCertificatePkcs10(certificateProfileId, profile, false, true, true, true);
        } finally {
            certificateProfileSession.removeCertificateProfile(admin, TESTCA_NAME);
            endEntityProfileSession.removeEndEntityProfile(admin, TESTCA_NAME);
        }
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(TESTCA_NAME);
    }

    /**
     * Reconfigure CA, process a certificate request and assert that the right things were stored in the database.
     * @throws EndEntityProfileNotFoundException 
     */
    private void generateCertificatePkcs10(int certificateProfileId, CertificateProfile certificateProfile, boolean useCertReqHistory, boolean useUserStorage,
            boolean useCertificateStorage, boolean raw) throws AuthorizationDeniedException, RemoveException, CertificateParsingException,
            InvalidKeyException, InvalidAlgorithmParameterException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException, SignatureException, ObjectNotFoundException, CertificateException, ApprovalException, IOException,
            CreateException, UserDoesntFullfillEndEntityProfile, EjbcaException, CesecoreException, CertificateExtensionException,
            EndEntityProfileNotFoundException {
        LOG.trace(">generateCertificatePkcs10");
        LOG.info("useCertReqHistory=" + useCertReqHistory + " useUserStorage=" + useUserStorage + " useCertificateStorage=" + useCertificateStorage);
        reconfigureCA(useCertReqHistory, useUserStorage, useCertificateStorage);
        EndEntityInformation userData = getNewUserData(certificateProfileId);
        Certificate certificate = doPkcs10Request(userData, raw);
        assertNotNull("No certificate returned from PKCS#10 request.", certificate);
        assertEquals("UserData " + (useUserStorage ? "wasn't" : "was") + " available in database.", useUserStorage, userDataExists(userData));
        assertEquals("Certificate Request History " + (useCertReqHistory ? "wasn't" : " was") + " available in database.", useCertReqHistory,
                certificateRequestHistoryExists(certificate));
        assertEquals("Certificate " + (useCertificateStorage && certificateProfile.getUseCertificateStorage() ? "wasn't" : "was")
                + " available in database.", useCertificateStorage && certificateProfile.getUseCertificateStorage(), certificateExists(certificate));

        // Clean up what we can
        if (useUserStorage) {
            endEntityManagementSession.deleteUser(admin, userData.getUsername());
        }
        if (useCertReqHistory) {
            certReqHistoryProxySession.removeCertReqHistoryData(CertTools.getFingerprintAsString(certificate));
        }
        if (certificate != null) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        LOG.trace("<generateCertificatePkcs10");
    }

    /**
     * Assert that the CA is configured to store things as expected.
     * 
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private void assertCAConfig(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws CADoesntExistsException,
            AuthorizationDeniedException {
        CAInfo caInfo = caSession.getCAInfo(admin, TESTCA_NAME);
        assertEquals("CA has wrong useCertReqHistory setting: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CA has wrong useUserStorage setting: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CA has wrong useCertificateStorage setting: ", useCertificateStorage, caInfo.isUseCertificateStorage());
    }

    /**
     * Change CA configuration for what to store and assert that the changes were made.
     * 
     * @throws CADoesntExistsException
     */
    private void reconfigureCA(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws AuthorizationDeniedException,
            CADoesntExistsException {
        CAInfo caInfo = caSession.getCAInfo(admin, TESTCA_NAME);
        caInfo.setUseCertReqHistory(useCertReqHistory);
        caInfo.setUseUserStorage(useUserStorage);
        caInfo.setUseCertificateStorage(useCertificateStorage);
        assertEquals("CAInfo did not store useCertReqHistory setting correctly: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CAInfo did not store useUserStorage setting correctly: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CAInfo did not store useCertificateStorage setting correctly: ", useCertificateStorage, caInfo.isUseCertificateStorage());
        caAdminSession.editCA(admin, caInfo);
        assertCAConfig(useCertReqHistory, useUserStorage, useCertificateStorage);
    }

    private EndEntityInformation getNewUserData(int certificateProfileId) throws EndEntityProfileNotFoundException {
        String username = "throwAwayTest-" + random.nextInt();
        String password = "foo123";
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(TESTCA_NAME);
        EndEntityInformation userData = new EndEntityInformation(username, "CN=" + username, CaTestCase.getTestCAId(TESTCA_NAME), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certificateProfileId, null, null,
                SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        userData.setPassword(password);
        return userData;
    }

    /**
     * Generate a new keypair and PKCS#10 request and request a new certificate in a single transaction.
     * 
     * @param raw true if an encoded request should be sent, false if an EJBCA PKCS10RequestMessage should be used.
     */
    private Certificate doPkcs10Request(EndEntityInformation userData, boolean raw) throws InvalidAlgorithmParameterException,
            OperatorCreationException, IOException, CertificateParsingException, InvalidKeyException, CADoesntExistsException, NotFoundException,
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, ObjectNotFoundException,
            CertificateException, ApprovalException, AuthorizationDeniedException, CreateException, UserDoesntFullfillEndEntityProfile,
            EjbcaException, CesecoreException, CertificateExtensionException {
        Certificate ret;
        KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); // Use short keys, since this will be done many times
        byte[] rawPkcs10req = CertTools
                .genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=ignored"), rsakeys.getPublic(), new DERSet(),
                        rsakeys.getPrivate(), null).toASN1Structure().getEncoded();
        if (raw) {
            ret = CertTools.getCertfromByteArray(certificateRequestSession.processCertReq(admin, userData, new String(Base64.encode(rawPkcs10req)),
                    CertificateConstants.CERT_REQ_TYPE_PKCS10, null, CertificateConstants.CERT_RES_TYPE_CERTIFICATE));
        } else {
            PKCS10RequestMessage pkcs10req = new PKCS10RequestMessage(rawPkcs10req);
            pkcs10req.setUsername(userData.getUsername());
            pkcs10req.setPassword(userData.getPassword());
            ret = ((X509ResponseMessage) certificateRequestSession.processCertReq(admin, userData, pkcs10req, X509ResponseMessage.class))
                    .getCertificate();
        }
        return ret;

    }

    private boolean userDataExists(EndEntityInformation userData) {
        return endEntityManagementSession.existsUser(userData.getUsername());
    }

    private boolean certificateRequestHistoryExists(Certificate certificate) {
        return certReqHistoryProxySession.retrieveCertReqHistory(CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate)) != null;
    }

    private boolean certificateExists(Certificate certificate) {
        return certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(certificate)) != null;
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
