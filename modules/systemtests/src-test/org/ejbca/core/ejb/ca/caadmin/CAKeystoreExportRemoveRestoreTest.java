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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
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

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private CAAdminTestSessionRemote catestsession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminTestSessionRemote.class);
    
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

        CATokenInfo catokeninfo = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        exportRemoveRestore(catokeninfo);

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

        CATokenInfo catokeninfo = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        exportRemoveRestore(catokeninfo);

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

        CATokenInfo catokeninfo = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, "secp256r1", AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        exportRemoveRestore(catokeninfo);

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

        CATokenInfo catokeninfo = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, "1024", AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        exportRemoveRestore(catokeninfo);

        log.trace("<test04ExportRemoveRestoreSHA1WithDSAForSigning()");
    }

    /**
     * Tests that it is not possible to accidentally restore the wrong keystore.
     * 
     * @throws Exception
     */
    @Test
    public void test05RestoreWrong() throws Exception {
        log.trace(">test05RestoreWrong()");

        String capassword = "foo123";
        byte[] keystorebytes1 = null;
        byte[] keystorebytes2 = null;
        byte[] keystorebytes3 = null;

        // CA using SHA1withRSA and 2048 bit RSA KEY
        String caname1 = "TestExportRemoveRestoreCA1";
        CATokenInfo catokeninfo1 = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo cainfo1 = getNewCAInfo(caname1, catokeninfo1);

        // This CA uses DSA instead
        String caname2 = "TestExportRemoveRestoreCA2";
        CATokenInfo catokeninfo2 = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo cainfo2 = getNewCAInfo(caname2, catokeninfo2);

        // This CA uses RSA but with 1024 bits
        String caname3 = "TestExportRemoveRestoreCA3";
        CATokenInfo catokeninfo3 = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo cainfo3 = getNewCAInfo(caname3, catokeninfo3);

        // Remove CAs if they already exists
        try {
            caSession.removeCA(internalAdmin, cainfo1.getCAId());
        } catch (Exception ignored) {
        }
        try {
            caSession.removeCA(internalAdmin, cainfo2.getCAId());
        } catch (Exception ignored) {
        }
        try {
            caSession.removeCA(internalAdmin, cainfo3.getCAId());
        } catch (Exception ignored) {
        }

        // Create CAs
        try {
            caAdminSession.createCA(internalAdmin, cainfo1);
        } catch (Exception e) {
            log.error("createCA", e);
            fail("createCA: " + e.getMessage());
        }
        try {
            caAdminSession.createCA(internalAdmin, cainfo2);
        } catch (Exception e) {
            log.error("createCA", e);
            fail("createCA: " + e.getMessage());
        }
        try {
            caAdminSession.createCA(internalAdmin, cainfo3);
        } catch (Exception e) {
            log.error("createCA", e);
            fail("createCA: " + e.getMessage());
        }

        // Export keystores
        try {
            keystorebytes1 = caAdminSession.exportCAKeyStore(internalAdmin, caname1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("exportCAKeyStore", e);
            fail("exportCAKeyStore: " + e.getMessage());
        }
        try {
            keystorebytes2 = caAdminSession.exportCAKeyStore(internalAdmin, caname2, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("exportCAKeyStore", e);
            fail("exportCAKeyStore: " + e.getMessage());
        }
        try {
            keystorebytes3 = caAdminSession.exportCAKeyStore(internalAdmin, caname3, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("exportCAKeyStore", e);
            fail("exportCAKeyStore: " + e.getMessage());
        }

        // Remove keystore from CA1
        try {
            caAdminSession.removeCAKeyStore(internalAdmin, caname1);
        } catch (Exception e) {
            log.error("removeKeyStores", e);
            fail("removeKeyStores: " + e.getMessage());
        }

        // Try to restore with wrong keystore
        try {
            caAdminSession.restoreCAKeyStore(internalAdmin, caname1, keystorebytes2, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            fail("Should not be possible to restore with a keystore with different parameters");
        } catch (Exception e) {
            // OK
        }
        try {
            caAdminSession.restoreCAKeyStore(internalAdmin, caname1, keystorebytes3, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            fail("Should not be possible to restore with a keystore with different parameters");
        } catch (Exception e) {
            // OK
        }

        // Finally try with the right keystore to see that it works
        try {
            caAdminSession.restoreCAKeyStore(internalAdmin, caname1, keystorebytes1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("restoreCAKeyStore", e);
            fail("restoreCAKeyStore: " + e.getMessage());
        }

        // Clean up
        try {
            caSession.removeCA(internalAdmin, cainfo1.getCAId());
        } catch (Exception e) {
            log.error("removeCA", e);
            fail("removeCA: " + e.getMessage());
        }
        try {
            caSession.removeCA(internalAdmin, cainfo2.getCAId());
        } catch (Exception e) {
            log.error("removeCA", e);
            fail("removeCA: " + e.getMessage());
        }
        try {
            caSession.removeCA(internalAdmin, cainfo3.getCAId());
        } catch (Exception e) {
            log.error("removeCA", e);
            fail("removeCA: " + e.getMessage());
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
        log.trace(">test06RestoreNotRemoved()");

        String capassword = "foo123";
        byte[] keystorebytes1 = null;

        // CA1
        String caname1 = "TestExportRemoveRestoreCA1";
        CATokenInfo catokeninfo = CAImportExportTest.createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo cainfo1 = getNewCAInfo(caname1, catokeninfo);

        // Remove if they already exists
        try {
            caSession.removeCA(internalAdmin, cainfo1.getCAId());
        } catch (Exception ignored) {
        }

        // Create CAs
        try {
            caAdminSession.createCA(internalAdmin, cainfo1);
        } catch (Exception e) {
            log.error("createCA", e);
            fail("createCA: " + e.getMessage());
        }

        // Export keystore
        try {
            keystorebytes1 = caAdminSession.exportCAKeyStore(internalAdmin, caname1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("exportCAKeyStore", e);
            fail("exportCAKeyStore: " + e.getMessage());
        }

        // Just created CA should be active
        CAInfo info = caSession.getCAInfo(internalAdmin, caname1);
        assertEquals("active token", CryptoToken.STATUS_ACTIVE, info.getCATokenInfo().getTokenStatus());

        // Try to restore the first CA even do it has not been removed
        try {
            caAdminSession.restoreCAKeyStore(internalAdmin, caname1, keystorebytes1, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            fail("Should fail when trying to restore an online CA");
        } catch (Exception e) {
            // OK
        }

        // Clean up
        try {
            caSession.removeCA(internalAdmin, cainfo1.getCAId());
        } catch (Exception e) {
            log.error("removeCA", e);
            fail("removeCA: " + e.getMessage());
        }

        log.trace("<test06RestoreNotRemoved()");
    }

    /**
     * Does export, remove and restore and performs tests.
     * 
     * @param catokeninfo
     *            Information with algorithm and key selections
     * @throws Exception
     */
    private void exportRemoveRestore(CATokenInfo catokeninfo) throws Exception {
        byte[] keystorebytes = null;
        String caname = "TestExportRemoveRestoreCA1";
        String capassword = "foo123";
        String keyFingerPrint = null;

        X509CAInfo cainfo = getNewCAInfo(caname, catokeninfo);
      
        // Remove if it already exists
        try {
            caSession.removeCA(internalAdmin, cainfo.getCAId());
        } catch (Exception ignored) {
        }

        // Create CA
        try {
            caAdminSession.createCA(internalAdmin, cainfo);
        } catch (Exception e) {
            log.error("createCA", e);
            fail("createCA: " + e.getMessage());
        }

        try {
            keyFingerPrint = catestsession.getKeyFingerPrint(caname);
        } catch (Exception e) {
            log.error("getKeyFingerPrint", e);
            fail("getKeyFingerPrint: " + e.getMessage());
        }

        try {
            keystorebytes = caAdminSession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");

        } catch (Exception e) {
            log.error("exportCAKeyStore", e);
            fail("exportCAKeyStore: " + e.getMessage());
        }

        // Remove the ca token soft keystore
        try {
            caAdminSession.removeCAKeyStore(internalAdmin, caname);
        } catch (Exception e) {
            log.error("removeKeyStores", e);
            fail("removeKeyStores: " + e.getMessage());
        }

        // The token should now be offline
        CAInfo info = caSession.getCAInfo(internalAdmin, caname);
        assertEquals("offline token", CryptoToken.STATUS_OFFLINE, info.getCATokenInfo().getTokenStatus());

        // Should not be possible to activate
        caAdminSession.activateCAToken(internalAdmin, cainfo.getCAId(), capassword, globalConfigurationSession.getCachedGlobalConfiguration());
        info = caSession.getCAInfo(internalAdmin, caname);
        assertEquals("offline token", CryptoToken.STATUS_OFFLINE, info.getCATokenInfo().getTokenStatus());

        // Should not be possible to export
        try {
            byte[] emptyBytes = caAdminSession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            assertEquals("empty keystore", 0, emptyBytes.length);
        } catch (Exception ignored) {
            // OK
        }

        try {
            String emptyFingerprint = catestsession.getKeyFingerPrint(caname);
            log.error("Got fingerprint: " + emptyFingerprint);
            fail("Should not have got a fingerprint");
        } catch (Exception e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            if (root instanceof CryptoTokenOfflineException) {
                // OK
            } else {
                log.error("getKeyFingerPrint", e);
                fail("getKeyFingerPrint: " + e.getMessage());
            }
        }

        // Restore keystore
        try {
            caAdminSession.restoreCAKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
        } catch (Exception e) {
            log.error("restoreKeyStores", e);
            fail("restoreKeyStores: " + e.getMessage());
        }

        // Compare fingerprints
        try {
            String restoredFingerprint = catestsession.getKeyFingerPrint(caname);
            assertEquals("restored fingerprint", keyFingerPrint, restoredFingerprint);
        } catch (Exception e) {
            log.error("getKeyFingerPrint2", e);
            fail("getKeyFingerPrint2: " + e.getMessage());
        }

        // Clean up
        try {
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
    private X509CAInfo getNewCAInfo(String caname, CATokenInfo catokeninfo) {
        X509CAInfo cainfo = new X509CAInfo("CN=" + caname, caname, CAConstants.CA_ACTIVE, new Date(), "", CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, new Date(System
                .currentTimeMillis()
                + 364 * 24 * 3600 * 1000), // Expiretime
                CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, null, // certificatechain
                catokeninfo, "Used for testing CA keystore export, remove and restore",
                -1, // revocationReason
                null, // revocationDate
                new ArrayList<CertificatePolicy>(), // PolicyId
                24, // CRLPeriod
                0, // CRLIssuePeriod
                10, // CRLOverlapTime
                0, // DeltaCRLOverlapTime
                new ArrayList<Integer>(), // crlpublishers 
                true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                "", // Default CRL Dist Point
                "", // Default CRL Issuer
                "", // Default OCSP Service Locator
                null, // Authority Information Access
                null, // defaultfreshestcrl
                true, // Finish User
                new ArrayList<ExtendedCAServiceInfo>(), // extendedcaservices
                false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, // include in health check
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null // cmpRaAuthSecret
        );
        return cainfo;
    }
}
