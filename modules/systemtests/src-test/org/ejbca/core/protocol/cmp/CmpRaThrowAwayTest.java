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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistoryProxySessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
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
    private static final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpRaThrowAwayTest"));
    private static final Random RND = new SecureRandom();

    private static final String TESTCA_NAME = "CmpRaThrowAwayTestCA";
    private static final String PBE_SECRET = "password";

    private static X509Certificate caCertificate;
    
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    private CmpConfiguration cmpConfiguration;
    private String configAlias = "CmpRaThrowAwayTestCmpConfigAlias";

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA(TESTCA_NAME); // Create test CA
    }

    /** Create CA and change configuration for the following tests. */
    @Before
    public void setUp() throws Exception {
        super.setUp();
        LOG.trace(">test000Setup");
       
        caCertificate = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, getTestCAId(TESTCA_NAME)).getCertificateChain().iterator()
                .next();
        assertCAConfig(false, true, true);
        
        // Configure CMP for this test. RA mode with individual shared PBE secrets for each CA.
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        cmpConfiguration.addAlias(configAlias);
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        cmpConfiguration.setResponseProtection(configAlias, "pbe");
        cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        cmpConfiguration.setRANameGenParams(configAlias, "CN");
        cmpConfiguration.setRAEEProfile(configAlias, "EMPTY");
        cmpConfiguration.setRACertProfile(configAlias, "ENDUSER");
        cmpConfiguration.setRACAName(configAlias, TESTCA_NAME);
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "-;" + PBE_SECRET);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        LOG.trace("<test000Setup");
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        LOG.trace(">testZZZTearDown");
        removeTestCA(TESTCA_NAME);
        cmpConfiguration.removeAlias(configAlias);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
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
        String subjectDN = "CN=" + username;
        PKIMessage one = genCertReq(CertTools.getSubjectDN(caCertificate), subjectDN, keys, caCertificate, nonce, transid, true, null, notBefore,
                notAfter, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBE_SECRET, "unusedKeyId", 567);
        assertNotNull("Request was not created properly.", req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req);
        byte[] resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(subjectDN, caCertificate, resp, reqId);
        assertEquals("Certificate history data was or wasn't stored: ", useCertReqHistory, EjbRemoteHelper.INSTANCE.getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                .retrieveCertReqHistory(CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert)) != null);
        assertEquals("User data was or wasn't stored: ", useUserStorage, EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser(username));
        assertEquals("Certificate data was or wasn't stored: ", useCertificateStorage, EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                .findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) != null);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, caCertificate, nonce, transid, hash, reqId);
        assertNotNull("Could not create confirmation message.", confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBE_SECRET, "unusedKeyId", 567);
        bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req1);
        resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(subjectDN, caCertificate, resp);

        // We only expect revocation to work if we store certificate data and user data
        // TODO: ECA-1916 should remove dependency on useUserStorage
        if (useCertificateStorage && useUserStorage) {
            // Now revoke the bastard using the CMPv1 reason code!
            PKIMessage rev = genRevReq(CertTools.getSubjectDN(caCertificate), subjectDN, cert.getSerialNumber(), caCertificate, nonce, transid, false, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBE_SECRET, "unusedKeyId", 567);
            assertNotNull("Could not create revocation message.", revReq);
            bao = new ByteArrayOutputStream();
            new DEROutputStream(bao).writeObject(revReq);
            resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
            checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpRevokeConfirmMessage(CertTools.getSubjectDN(caCertificate), subjectDN, cert.getSerialNumber(), caCertificate, resp, true);
            int reason = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getStatus(CertTools.getSubjectDN(caCertificate), cert.getSerialNumber()).revocationReason;
            assertEquals("Certificate was not revoked with the right reason.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, reason);
        }
        // Clean up what we can
        if (useUserStorage) {
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(ADMIN, username);
        }
        if (useCertReqHistory) {
            EjbRemoteHelper.INSTANCE.getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST).removeCertReqHistoryData(CertTools.getFingerprintAsString(cert));
        }
        LOG.trace("<testIssueConfirmRevoke");
    }

    /** Assert that the CA is configured to store things as expected. 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException */
    private void assertCAConfig(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws CADoesntExistsException, AuthorizationDeniedException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        assertEquals("CA has wrong useCertReqHistory setting: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CA has wrong useUserStorage setting: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CA has wrong useCertificateStorage setting: ", useCertificateStorage, caInfo.isUseCertificateStorage());
    }

    /** Change CA configuration for what to store and assert that the changes were made. 
     * @throws CADoesntExistsException */
    private void reconfigureCA(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws AuthorizationDeniedException, CADoesntExistsException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        caInfo.setUseCertReqHistory(useCertReqHistory);
        caInfo.setUseUserStorage(useUserStorage);
        caInfo.setUseCertificateStorage(useCertificateStorage);
        assertEquals("CAInfo did not store useCertReqHistory setting correctly: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CAInfo did not store useUserStorage setting correctly: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CAInfo did not store useCertificateStorage setting correctly: ", useCertificateStorage, caInfo.isUseCertificateStorage());
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(ADMIN, caInfo);
        assertCAConfig(useCertReqHistory, useUserStorage, useCertificateStorage);
    }
}
