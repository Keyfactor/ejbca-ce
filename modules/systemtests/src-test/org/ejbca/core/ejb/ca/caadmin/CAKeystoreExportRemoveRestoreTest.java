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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for the Soft catoken removal functionality.
 * 
 * A CA keystore can be exported using caAdminSessionBean.exportCAKeyStore(). A
 * CA keystore can be removed using caAdminSessionBean.removeCAKeyStore(). A CA
 * keystore can be restored using caAdminSessionBean.restoreCAKeyStore().
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class CAKeystoreExportRemoveRestoreTest {

    private static final Logger log = Logger.getLogger(CAKeystoreExportRemoveRestoreTest.class);

    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CAAdminTestSessionRemote caAdminTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAKeystoreExportRemoveRestoreTest"));

    @BeforeClass
    public static void installProvider() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    /**
     * Setup test environment.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
    }

    /**
     * Tear down test environment. Does nothing.
     * 
     * @throws Exception
     */
    @After
    public void tearDown() throws Exception {
    }

    /**
     * Tries to export, remove and restore with a CA that is using SHA1withRSA
     * as signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test01ExportRemoveRestoreSHA1WithRSA() throws Exception {
        log.trace("<test01ExportRemoveRestoreSHA1WithRSA()");
        subTestExportRemoveRestore("test01", "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        log.trace("<test01ExportRemoveRestoreSHA1WithRSA()");
    }

    /**
     * Tries to export, remove and restore with a CA that is using SHA256withRSA
     * and 1024 bit RSA key for signing but SHA1WithRSA and a RSA 2048 bit key
     * for encryption.
     * 
     * @throws Exception
     */
    @Test
    public void test02ExportRemoveRestoreSHA256WithRSAForSigning() throws Exception {
        log.trace(">test02ExportRemoveRestoreSHA256WithRSAForSigning()");
        subTestExportRemoveRestore("test02", "1024", AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        log.trace("<test02ExportRemoveRestoreSHA256WithRSAForSigning()");
    }

    /**
     * Tries to export, remove and restore with a CA that is using SHA1withECDSA
     * and a key using the secp256r1 curve for signing but SHA256WithRSA and a
     * 1024 bit RSA key for encryption.
     * 
     * @throws Exception
     */
    @Test
    public void test03ExportRemoveRestoreSHA1WithECDSAForSigning() throws Exception {
        log.trace(">test03ExportRemoveRestoreSHA1WithECDSAForSigning()");
        subTestExportRemoveRestore("test03", "secp256r1", AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        log.trace("<test03ExportRemoveRestoreSHA1WithECDSAForSigning()");
    }

    /**
     * Tries to export, remove and restore with a CA that is using SHA1withDSA
     * and a 1024 bit DSA key for signing but SHA256WithRSA and a 1024 bit RSA
     * key for encryption.
     * 
     * @throws Exception
     */
    @Test
    public void test04ExportRemoveRestoreSHA1WithDSAForSigning() throws Exception {
        log.trace(">test04ExportRemoveRestoreSHA1WithDSAForSigning()");
        subTestExportRemoveRestore("test04", "DSA1024", AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        log.trace("<test04ExportRemoveRestoreSHA1WithDSAForSigning()");
    }

    /** Create CryptoToken, generates keys, executes test and cleans up CryptoToken. */
    private void subTestExportRemoveRestore(String cryptoTokenName, String signKeySpecification, String signatureAlgorithm, String encryptionAlgorithm) throws Exception {
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "foo123".toCharArray(), cryptoTokenName, signKeySpecification);
            CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, signatureAlgorithm, encryptionAlgorithm);
            exportRemoveRestore(catoken);
        } finally {
            // Remove original keystore if it would still exist
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
    }
    
    /**
     * Tests that it is not possible to accidentally restore the wrong keystore.
     * 
     * @throws Exception
     */
    @Test
    public void test05RestoreWrong() throws Exception {
        final String capassword = "foo123";
        log.trace(">test05RestoreWrong()");
        int cryptoTokenId1 = 0;
        int cryptoTokenId2 = 0;
        int cryptoTokenId3 = 0;
        try {
            // CA using SHA1withRSA and 2048 bit RSA KEY
            final String CANAME1 = "TestExportRemoveRestoreCA1";
            cryptoTokenId1 = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, capassword.toCharArray(), CANAME1, "1024");
            final CAToken catoken1 = CaTestUtils.createCaToken(cryptoTokenId1, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            final X509CAInfo cainfo1 = getNewCAInfo(CANAME1, catoken1);
            // This CA uses DSA instead
            final String CANAME2 = "TestExportRemoveRestoreCA2";
            cryptoTokenId2 = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, capassword.toCharArray(), CANAME2, "DSA1024");
            final CAToken catoken2 = CaTestUtils.createCaToken(cryptoTokenId2, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            final X509CAInfo cainfo2 = getNewCAInfo(CANAME2, catoken2);
            // This CA uses RSA but with 1024 bits
            final String CANAME3 = "TestExportRemoveRestoreCA3";
            cryptoTokenId3 = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, capassword.toCharArray(), CANAME3, "1024");
            final CAToken catoken3 = CaTestUtils.createCaToken(cryptoTokenId3, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            final X509CAInfo cainfo3 = getNewCAInfo(CANAME3, catoken3);
            // Remove CAs if they already exists
            caSession.removeCA(internalAdmin, cainfo1.getCAId());
            caSession.removeCA(internalAdmin, cainfo2.getCAId());
            caSession.removeCA(internalAdmin, cainfo3.getCAId());
            // Create CAs
            caAdminSession.createCA(internalAdmin, cainfo1);
            caAdminSession.createCA(internalAdmin, cainfo2);
            caAdminSession.createCA(internalAdmin, cainfo3);
            try {
                // Export keystores
                byte[] keystorebytes1 = caAdminSession.exportCAKeyStore(internalAdmin, CANAME1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                byte[] keystorebytes2 = caAdminSession.exportCAKeyStore(internalAdmin, CANAME2, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                byte[] keystorebytes3 = caAdminSession.exportCAKeyStore(internalAdmin, CANAME3, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                // Remove keystore from CA1
                try {
                    caAdminSession.removeCAKeyStore(internalAdmin, CANAME1);
                } catch (Exception e) {
                    log.error("removeKeyStores", e);
                    fail("removeKeyStores: " + e.getMessage());
                }
                // Try to restore with wrong keystore
                try {
                    caAdminSession.restoreCAKeyStore(internalAdmin, CANAME1, keystorebytes2, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                    fail("Should not be possible to restore with a keystore with different parameters");
                } catch (Exception e) {
                    // OK. EJBException -> InvalidKeyException (DSA keystore to RSA CA)
                    log.debug("", e);
                }
                try {
                    caAdminSession.restoreCAKeyStore(internalAdmin, CANAME1, keystorebytes3, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                    fail("Should not be possible to restore with a keystore with different parameters");
                } catch (Exception e) {
                    // OK. EJBException -> Exception "Could not use private key for verification. Wrong p12-file for this CA"
                    log.debug("", e);
                }
                // Finally try with the right keystore to see that it works
                caAdminSession.restoreCAKeyStore(internalAdmin, CANAME1, keystorebytes1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                final CAInfo caInfo = caSession.getCAInfo(internalAdmin, CANAME1);
                CryptoTokenTestUtils.removeCryptoToken(internalAdmin, caInfo.getCAToken().getCryptoTokenId());
            } finally {
                // Clean up CAs
                caSession.removeCA(internalAdmin, cainfo1.getCAId());
                caSession.removeCA(internalAdmin, cainfo2.getCAId());
                caSession.removeCA(internalAdmin, cainfo3.getCAId());
            }
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId1);
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId2);
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId3);
        }
        log.trace("<test05RestoreWrong()");
    }

    /**
     * Tests that it is not possible to restore a CA that has not been removed
     * (or at least not one with an active CA token).
     * 
     * @throws Exception
     */
    @Test
    public void test06RestoreNotRemoved() throws Exception {
        final String capassword = "foo123";
        log.trace(">test06RestoreNotRemoved()");
        int cryptoTokenId = 0;
        try {
            // CA using SHA1withRSA and 2048 bit RSA KEY
            final String CANAME = "TestExportRemoveRestoreCA1";
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, capassword.toCharArray(), CANAME, "1024");
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            final X509CAInfo cainfo = getNewCAInfo(CANAME, catoken);

            byte[] keystorebytes1 = null;
            // Remove if they already exists
            caSession.removeCA(internalAdmin, cainfo.getCAId());
            // Create CAs
            caAdminSession.createCA(internalAdmin, cainfo);
            keystorebytes1 = caAdminSession.exportCAKeyStore(internalAdmin, CANAME, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            // Just created CA should be active
            CAInfo info = caSession.getCAInfo(internalAdmin, CANAME);
            assertEquals("An active CA Service was expected", CAConstants.CA_ACTIVE, info.getStatus());
            final boolean isCryptoTokenStatusActive = cryptoTokenManagementSession.isCryptoTokenStatusActive(internalAdmin, cryptoTokenId);
            assertTrue("An active CA CryptoToken was expected", isCryptoTokenStatusActive);
            // Try to restore the first CA even do it has not been removed
            try {
                caAdminSession.restoreCAKeyStore(internalAdmin, CANAME, keystorebytes1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                fail("Should fail when trying to restore an online CA");
            } catch (Exception e) {
                // OK. EJBException -> Exception: "CA already has an existing CryptoToken reference: nnn..."
                log.debug("", e);
            }
            // Clean up
            caSession.removeCA(internalAdmin, cainfo.getCAId());
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
        log.trace("<test06RestoreNotRemoved()");
    }

    /**
     * Does export, remove and restore and performs tests.
     * 
     * @param catoken
     *            Information with algorithm and key selections
     * @throws Exception
     */
    private void exportRemoveRestore(CAToken catoken) throws Exception {
        final int cryptoTokenId = catoken.getCryptoTokenId();
        String caname = "TestExportRemoveRestoreCA1";
        String capassword = "foo123";
        X509CAInfo cainfo = getNewCAInfo(caname, catoken);
        // Remove if it already exists
        caSession.removeCA(internalAdmin, cainfo.getCAId());
        // Create CA
        caAdminSession.createCA(internalAdmin, cainfo);
        String keyFingerPrint = caAdminTestSession.getKeyFingerPrint(caname);
        byte[] keystorebytes = caAdminSession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        // Remove the ca token soft keystore
        caAdminSession.removeCAKeyStore(internalAdmin, caname);
        // The token should now be offline
        CAInfo info = caSession.getCAInfo(internalAdmin, caname);
        assertEquals("An offline CA Service was expected", CAConstants.CA_OFFLINE, info.getStatus());
        try {
            cryptoTokenManagementSession.isCryptoTokenStatusActive(internalAdmin, cryptoTokenId);
            fail("We expect a removed CA keystore to remove a soft CryptoToken entirely.");
        } catch (Exception e) {
            // Ok
        }
        // Should not be possible to activate
        caAdminSession.activateCAService(internalAdmin, cainfo.getCAId());
        info = caSession.getCAInfo(internalAdmin, caname);
        assertEquals("Unpected CryptoToken reference.", 0, info.getCAToken().getCryptoTokenId());
        // Should not be possible to export
        try {
            byte[] emptyBytes = caAdminSession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            assertEquals("empty keystore", 0, emptyBytes.length);
        } catch (Exception ignored) {
            // OK
        }
        try {
            String emptyFingerprint = caAdminTestSession.getKeyFingerPrint(caname);
            log.error("Got fingerprint: " + emptyFingerprint);
            fail("Should not have got a fingerprint");
        } catch (Exception e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            if (root instanceof IllegalCryptoTokenException) {
                // OK
            } else {
                log.error("getKeyFingerPrint", e);
                fail("getKeyFingerPrint: " + e.getMessage());
            }
        }
        // Restore keystore
        caAdminSession.restoreCAKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        // Compare fingerprints
        try {
            String restoredFingerprint = caAdminTestSession.getKeyFingerPrint(caname);
            assertEquals("restored fingerprint", keyFingerPrint, restoredFingerprint);
        } catch (Exception e) {
            log.error("getKeyFingerPrint2", e);
            fail("getKeyFingerPrint2: " + e.getMessage());
        }
        // Clean up
        try {
            // The imported CA CryptoToken will have a different ID than the exported.
            final CAInfo caInfo = caSession.getCAInfo(internalAdmin, cainfo.getCAId());
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, caInfo.getCAToken().getCryptoTokenId());
            caSession.removeCA(internalAdmin, cainfo.getCAId());
        } catch (Exception e) {
            log.error("removeCA", e);
            fail("removeCA: " + e.getMessage());
        }
    }

    /**
     * Creates a CAinfo for testing.
     * 
     * @param caname
     *            The name this CA-info will be assigned
     * @param catokeninfo
     *            The tokeninfo for this CA-info
     * @return The new X509CAInfo for testing.
     */
    private X509CAInfo getNewCAInfo(String caname, CAToken catoken) {
        X509CAInfo cainfo = new X509CAInfo("CN=" + caname, caname, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setExpireTime(new Date(System.currentTimeMillis() + 364 * 24 * 3600 * 1000));
        cainfo.setDescription("Used for testing CA keystore export, remove and restore");
        return cainfo;
    }
}
