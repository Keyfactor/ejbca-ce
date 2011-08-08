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

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.CertTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.util.InterfaceCache;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Verify that CMP functionality works in RA mode, when any combination of - useCertReqHistory (Store copy of UserData at the time of certificate
 * issuance.) - useUserStorage (Store current UserData.) - useCertificateStorage (Store issued certificates and related information.) are used.
 * 
 * @version $Id$
 */
public class CmpRaThrowAwayTest extends CmpTestCase {

    private static final Logger LOG = Logger.getLogger(CmpRAAuthenticationTest.class);
    private static final AuthenticationToken ADMIN = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private static final Random RND = new SecureRandom();

    private static final String TESTCA_NAME = "CmpRaThrowAwayTestCA";
    private static final String PBE_SECRET = "password";

    private static X509Certificate caCertificate;

    public CmpRaThrowAwayTest(String name) {
        super(name);
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    /** Create CA and change configuration for the following tests. */
    public void test000Setup() throws Exception {
        LOG.trace(">test000Setup");
        createTestCA(TESTCA_NAME); // Create test CA
        caCertificate = (X509Certificate) InterfaceCache.getCaSession().getCAInfo(ADMIN, getTestCAId(TESTCA_NAME)).getCertificateChain().iterator()
                .next();
        assertCAConfig(true, true, true);
        // Configure CMP for this test. RA mode with individual shared PBE secrets for each CA.
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBE_SECRET);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, TESTCA_NAME);
        LOG.trace("<test000Setup");
    }

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

    public void testZZZTearDown() throws Exception {
        LOG.trace(">testZZZTearDown");
        boolean cleanUpOk = true;
        cleanUpOk &= InterfaceCache.getConfigurationSession().restoreConfiguration();
        cleanUpOk &= removeTestCA(TESTCA_NAME);
        assertTrue("Clean up failed!", cleanUpOk);
        LOG.trace("<testZZZTearDown");
    }

    /**
     * Sends a certificate request message and verifies result. Sends a confirm message and verifies result. Sends a revocation message and verifies
     * result. (If we save certificate data!)
     */
    public void testIssueConfirmRevoke(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws Exception {
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
                notAfter, null);
        PKIMessage req = protectPKIMessage(one, false, PBE_SECRET, "unusedKeyId", 567);
        assertNotNull("Request was not created properly.", req);
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req);
        byte[] resp = sendCmpHttp(bao.toByteArray(), 200);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET);
        X509Certificate cert = checkCmpCertRepMessage(subjectDN, caCertificate, resp, reqId);
        assertEquals("Certificate history data was or wasn't stored: ", useCertReqHistory, InterfaceCache.getCertReqHistorySession()
                .retrieveCertReqHistory(ADMIN, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert)) != null);
        assertEquals("User data was or wasn't stored: ", useUserStorage, InterfaceCache.getUserAdminSession().existsUser(ADMIN, username));
        assertEquals("Certificate data was or wasn't stored: ", useCertificateStorage, InterfaceCache.getCertificateStoreSession()
                .findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) != null);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, caCertificate, nonce, transid, hash, reqId);
        assertNotNull("Could not create confirmation message.", confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBE_SECRET, "unusedKeyId", 567);
        bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req1);
        resp = sendCmpHttp(bao.toByteArray(), 200);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET);
        checkCmpPKIConfirmMessage(subjectDN, caCertificate, resp);

        // We only expect revocation to work if we store certificate data and user data
        // TODO: ECA-1916 should remove dependency on useUserStorage
        if (useCertificateStorage && useUserStorage) {
            // Now revoke the bastard using the CMPv1 reason code!
            PKIMessage rev = genRevReq(CertTools.getSubjectDN(caCertificate), subjectDN, cert.getSerialNumber(), caCertificate, nonce, transid, false);
            PKIMessage revReq = protectPKIMessage(rev, false, PBE_SECRET, "unusedKeyId", 567);
            assertNotNull("Could not create revocation message.", revReq);
            bao = new ByteArrayOutputStream();
            new DEROutputStream(bao).writeObject(revReq);
            resp = sendCmpHttp(bao.toByteArray(), 200);
            checkCmpResponseGeneral(resp, CertTools.getSubjectDN(caCertificate), subjectDN, caCertificate, nonce, transid, false, PBE_SECRET);
            checkCmpRevokeConfirmMessage(CertTools.getSubjectDN(caCertificate), subjectDN, cert.getSerialNumber(), caCertificate, resp, true);
            int reason = InterfaceCache.getCertificateStoreSession().getStatus(CertTools.getSubjectDN(caCertificate), cert.getSerialNumber()).revocationReason;
            assertEquals("Certificate was not revoked with the right reason.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, reason);
        }
        // Clean up what we can
        if (useUserStorage) {
            InterfaceCache.getUserAdminSession().deleteUser(ADMIN, username);
        }
        if (useCertReqHistory) {
            InterfaceCache.getCertReqHistorySession().removeCertReqHistoryData(ADMIN, CertTools.getFingerprintAsString(cert));
        }
        LOG.trace("<testIssueConfirmRevoke");
    }

    /** Assert that the CA is configured to store things as expected. 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException */
    private void assertCAConfig(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws CADoesntExistsException, AuthorizationDeniedException {
        CAInfo caInfo = InterfaceCache.getCaSession().getCAInfo(ADMIN, TESTCA_NAME);
        assertEquals("CA has wrong useCertReqHistory setting: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CA has wrong useUserStorage setting: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CA has wrong useCertificateStorage setting: ", useCertificateStorage, caInfo.isUseCertificateStorage());
    }

    /** Change CA configuration for what to store and assert that the changes were made. 
     * @throws CADoesntExistsException */
    private void reconfigureCA(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws AuthorizationDeniedException, CADoesntExistsException {
        CAInfo caInfo = InterfaceCache.getCaSession().getCAInfo(ADMIN, TESTCA_NAME);
        caInfo.setUseCertReqHistory(useCertReqHistory);
        caInfo.setUseUserStorage(useUserStorage);
        caInfo.setUseCertificateStorage(useCertificateStorage);
        assertEquals("CAInfo did not store useCertReqHistory setting correctly: ", useCertReqHistory, caInfo.isUseCertReqHistory());
        assertEquals("CAInfo did not store useUserStorage setting correctly: ", useUserStorage, caInfo.isUseUserStorage());
        assertEquals("CAInfo did not store useCertificateStorage setting correctly: ", useCertificateStorage, caInfo.isUseCertificateStorage());
        InterfaceCache.getCAAdminSession().editCA(ADMIN, caInfo);
        assertCAConfig(useCertReqHistory, useUserStorage, useCertificateStorage);
    }
}
