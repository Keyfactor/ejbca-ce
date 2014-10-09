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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistoryProxySessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verify that CMP functionality works in RA mode, when any combination of - useCertReqHistory (Store copy of UserData at the time of certificate
 * issuance.) - useUserStorage (Store current UserData.) - useCertificateStorage (Store issued certificates and related information.) are used.
 * 
 * @version $Id$
 */
public class CmpRaThrowAwayTest extends CmpTestCase {

    private static final Logger LOG = Logger.getLogger(CmpRAAuthenticationTest.class);
    private static final Random RND = new SecureRandom();

    private static final String TESTCA_NAME = "CmpRaThrowAwayTestCA";
    private static final String PBE_SECRET = "password";

    private final  X509Certificate caCertificate;
    
    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final CertReqHistoryProxySessionRemote csrHistorySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private final CmpConfiguration cmpConfiguration;
    private final static String configAlias = "CmpRaThrowAwayTestCmpConfigAlias";

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA(TESTCA_NAME); // Create test CA
    }

    public CmpRaThrowAwayTest() throws Exception, Exception {
        this.caCertificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(
                CaSessionRemote.class).getCAInfo(ADMIN, getTestCAId(TESTCA_NAME)).getCertificateChain().iterator()
                .next();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    /** Create CA and change configuration for the following tests. */
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        LOG.trace(">test000Setup");
       
        assertCAConfig(false, true, true);
        
        // Configure CMP for this test. RA mode with individual shared PBE secrets for each CA.
        this.cmpConfiguration.addAlias(configAlias);
        this.cmpConfiguration.setRAMode(configAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        this.cmpConfiguration.setResponseProtection(configAlias, "pbe");
        this.cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        this.cmpConfiguration.setRANameGenParams(configAlias, "CN");
        this.cmpConfiguration.setRAEEProfile(configAlias, "EMPTY");
        this.cmpConfiguration.setRACertProfile(configAlias, "ENDUSER");
        this.cmpConfiguration.setRACAName(configAlias, TESTCA_NAME);
        this.cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(configAlias, "-;" + PBE_SECRET);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration, CmpConfiguration.CMP_CONFIGURATION_ID);
        LOG.trace("<test000Setup");
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        LOG.trace(">testZZZTearDown");
        removeTestCA(TESTCA_NAME);
        this.cmpConfiguration.removeAlias(configAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration, CmpConfiguration.CMP_CONFIGURATION_ID);
        LOG.trace("<testZZZTearDown");
    }

    @Test
    public void testIssueConfirmRevokeCombination1() throws Exception {
        LOG.trace(">testIssueConfirmRevokeCombination1");
        // Run through all possible configurations of what to store in the database
        for (int i = 0; i <= 7; i++) {
            boolean useCertReqHistory = (i & 1) != 0; // Bit 0
            boolean useUserStorage = (i & 2) != 0; // Bit 1
            boolean useCertificateStorage = (i & 4) != 0; // Bit 2
            reconfigureCA(useCertReqHistory, useUserStorage, useCertificateStorage);
            testIssueConfirmRevoke(useCertReqHistory, useUserStorage, useCertificateStorage);
        }
        LOG.trace("<testIssueConfirmRevokeCombination1");
    }


    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    /**
     * Sends a certificate request message and verifies result. Sends a confirm message and verifies result. Sends a revocation message and verifies
     * result. (If we save certificate data!)
     */
    private void testIssueConfirmRevoke(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws Exception {
        LOG.trace(">testIssueConfirmRevoke");
        LOG.info("useCertReqHistory=" + useCertReqHistory + " useUserStorage=" + useUserStorage + " useCertificateStorage=" + useCertificateStorage);
        // Generate and send certificate request
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        Date notBefore = new Date();
        Date notAfter = new Date(new Date().getTime() + 24 * 3600 * 1000);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        String username = "cmpRaThrowAwayTestUser" + RND.nextLong(); // This is what we expect from the CMP configuration
        final X500Name subjectDN = new X500Name("CN=" + username);
        PKIMessage one = genCertReq(CertTools.getSubjectDN(this.caCertificate), subjectDN, keys, this.caCertificate, nonce, transid, true, null, notBefore,
                notAfter, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBE_SECRET, "unusedKeyId", 567);
        assertNotNull("Request was not created properly.", req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req);
        byte[] resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(subjectDN, this.caCertificate, resp, reqId);
        assertTrue(
                "Certificate history data was or wasn't stored: ",
                useCertReqHistory ==
                (this.csrHistorySession.retrieveCertReqHistory(CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert)) != null)
                );
        assertTrue("User data was or wasn't stored: ", useUserStorage == this.endEntityManagementSession.existsUser(username));
        assertTrue(
                "Certificate data was or wasn't stored: ",
                useCertificateStorage == (this.certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) != null));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, this.caCertificate, nonce, transid, hash, reqId);
        assertNotNull("Could not create confirmation message.", confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBE_SECRET, "unusedKeyId", 567);
        bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req1);
        resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(subjectDN, this.caCertificate, resp);

        // We only expect revocation to work if we store certificate data and user data
        // TODO: ECA-1916 should remove dependency on useUserStorage
        if (useCertificateStorage && useUserStorage) {
            // Now revoke the bastard using the CMPv1 reason code!
            PKIMessage rev = genRevReq(CertTools.getSubjectDN(this.caCertificate), subjectDN, cert.getSerialNumber(), this.caCertificate, nonce, transid, false, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBE_SECRET, "unusedKeyId", 567);
            assertNotNull("Could not create revocation message.", revReq);
            bao = new ByteArrayOutputStream();
            new DEROutputStream(bao).writeObject(revReq);
            resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
            checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpRevokeConfirmMessage(CertTools.getSubjectDN(this.caCertificate), subjectDN, cert.getSerialNumber(), this.caCertificate, resp, true);
            int reason = this.certificateStoreSession.getStatus(CertTools.getSubjectDN(this.caCertificate), cert.getSerialNumber()).revocationReason;
            assertEquals("Certificate was not revoked with the right reason.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, reason);
        }
        // Clean up what we can
        if (useUserStorage) {
            this.endEntityManagementSession.deleteUser(ADMIN, username);
        }
        if (useCertReqHistory) {
            this.csrHistorySession.removeCertReqHistoryData(CertTools.getFingerprintAsString(cert));
        }
        LOG.trace("<testIssueConfirmRevoke");
    }

    /** Assert that the CA is configured to store things as expected. 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException */
    private static void assertCAConfig(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws CADoesntExistsException, AuthorizationDeniedException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        assertTrue("CA has wrong useCertReqHistory setting: ", useCertReqHistory == caInfo.isUseCertReqHistory());
        assertTrue("CA has wrong useUserStorage setting: ", useUserStorage == caInfo.isUseUserStorage());
        assertTrue("CA has wrong useCertificateStorage setting: ", useCertificateStorage == caInfo.isUseCertificateStorage());
    }

    /** Change CA configuration for what to store and assert that the changes were made. 
     * @throws CADoesntExistsException */
    private static void reconfigureCA(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws AuthorizationDeniedException, CADoesntExistsException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        caInfo.setUseCertReqHistory(useCertReqHistory);
        caInfo.setUseUserStorage(useUserStorage);
        caInfo.setUseCertificateStorage(useCertificateStorage);
        // We can not enforce unique subjectDN for issued certificates when we do not store certificates
        caInfo.setDoEnforceUniqueDistinguishedName(false);
        // We can not enforce unique subject public keys for issued certificates when we do not store certificates        
        caInfo.setDoEnforceUniquePublicKeys(false);
        assertTrue("CAInfo did not store useCertReqHistory setting correctly: ", useCertReqHistory == caInfo.isUseCertReqHistory());
        assertTrue("CAInfo did not store useUserStorage setting correctly: ", useUserStorage == caInfo.isUseUserStorage());
        assertTrue("CAInfo did not store useCertificateStorage setting correctly: ", useCertificateStorage == caInfo.isUseCertificateStorage());
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(ADMIN, caInfo);
        assertCAConfig(useCertReqHistory, useUserStorage, useCertificateStorage);
    }
}
