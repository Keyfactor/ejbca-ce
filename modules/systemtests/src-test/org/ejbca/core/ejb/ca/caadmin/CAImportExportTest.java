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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests CA import and export.
 * 
 * @version $Id$
 */
public class CAImportExportTest  {
    private static Logger log = Logger.getLogger(CAImportExportTest.class);
    private static X509CAInfo cainfo = null;
    
    private CAAdminSessionRemote caadminsession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CAAdminTestSessionRemote catestsession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CrlStoreSessionRemote crlStore = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static AuthenticationToken adminTokenNoAuth;
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAImportExportTest"));

    private static String TEST_PASSWORD = "foo123";

    @BeforeClass
    public static void beforeTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException, IOException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertProfileSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
    
    /** Tries to export and import a CA that is using SHA1withRSA as signature algorithm. */
    @Test
	public void test01ImportExportSHA1withRSA() throws Exception {
	    log.trace("<test01ImportExport..()");
	    final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test01", "1024");
	    try {
	        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
	        subTest(catoken);
	    } finally {
	        CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
	    }
	    log.trace("<test01ImportExport()");
	}

    /** Tries to export and import a CA that is using SHA1withECDSA as signature algorithm. */
    @Test
	public void test02ImportExportSHA1withECDSA() throws Exception {
	    log.trace("<test02ImportExport..()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test02", "prime256v1");
        try {
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            subTest(catoken);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
	    log.trace("<test02ImportExport()");
	}

    /** Tries to export and import a CA that is using SHA256withRSA as signature algorithm. */
    @Test
	public void test03ImportExportSHA256withRSA() throws Exception {
	    log.trace("<test03ImportExport..()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test03", "2048");
        try {
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            subTest(catoken);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
	    log.trace("<test03ImportExport()");
	}

    /** Tries to export and import a CA that is using SHA256withECDSA as signature algorithm. */
    @Test
	public void test04ImportExportSHA256withECDSA() throws Exception {
	    log.trace("<test04ImportExport..()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test04", "prime256v1");
        try {
            final CAToken catokeninfo = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            subTest(catokeninfo);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
	    log.trace("<test04ImportExport()");
	}

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm and assuming
     * the admin role of a "Public web user". This method tests that the accessrules are working for 
     * and the test will succeed if the commands fail.
     */
    @Test
	public void test05ImportExportAccess() throws Exception {
	    log.trace("<test05ImportExport..()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test05", "prime256v1");
        try {
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            subTestPublicAccess(catoken, adminTokenNoAuth);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
	    log.trace("<test05ImportExport()");
	}
	
	/**
     * Tries to export and import a CA that is using SHA1withDSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test06ImportExportSHA1withDSA() throws Exception {
	    log.trace("<test06ImportExport..()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test06", "DSA1024");
        try {
            final CAToken catokeninfo = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            subTest(catokeninfo);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
	    log.trace("<test06ImportExport()");
	}

    
    @Test
    public void test07ImportWithNewSession() throws Exception {
        log.trace("<test07Import...()");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, TEST_PASSWORD.toCharArray(), "test07", "1024");
        try {
            CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            byte[] keystorebytes = null;
            String caname = "DummyTestCA";
            String capassword = TEST_PASSWORD;
            cainfo = getNewCAInfo(caname, catoken);
            CAAdminSessionRemote caAdminSessionNew = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
            boolean defaultRetValue = true;

            // create CA in a new transaction, export the keystore from there
            caAdminSessionNew.createCA(internalAdmin, cainfo);
            keystorebytes = caAdminSessionNew.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");

            boolean ret = false;
            try {
                caSession.removeCA(internalAdmin, cainfo.getCAId());
                caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
                ret = true;
            } finally {
                final CAInfo caInfo = caSession.getCAInfo(internalAdmin, caname);
                CryptoTokenTestUtils.removeCryptoToken(internalAdmin, caInfo.getCAToken().getCryptoTokenId());
                caSession.removeCA(internalAdmin, caInfo.getCAId());
            }
            assertEquals("Could not import CA.", ret, defaultRetValue);
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
    }
    
    /** Tries to export of a CA with an incorrect password */
    @Test
    public void test08ExportWithWrongPassword() throws Exception {
        final String caname = "test08";
        log.trace("<test08ExportWithPassword..()");
        final char[] correctpwd = "correctpwd".toCharArray();
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, correctpwd, true, false, caname, "1024");
        try {
            // Make exportable
            CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(internalAdmin, cryptoTokenId);
            Properties properties = cryptoTokenInfo.getCryptoTokenProperties();
            properties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
            cryptoTokenManagementSession.saveCryptoToken(internalAdmin, cryptoTokenId, cryptoTokenInfo.getName(), properties, correctpwd);
            
            // Create CA
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            cainfo = getNewCAInfo(caname, catoken);
            try {
                caSession.removeCA(internalAdmin, cainfo.getCAId());
            } catch (Exception e) { 
                // NOPMD
            }
            caadminsession.createCA(internalAdmin, cainfo);
            
            // Try exporting with the wrong password
            // The return values are ignored. The calls should throw exceptions
            try {
                caadminsession.exportCAKeyStore(internalAdmin, caname, "wrongpwd", "wrongpwd", "SignatureKeyAlias", "EncryptionKeyAlias");
                fail("Was able to export CA keystore with the wrong password!");
            } catch (Exception e) {
                // NOPMD
            }
            
            try {
                caadminsession.exportCAKeyStore(internalAdmin, caname, null, null, "SignatureKeyAlias", "EncryptionKeyAlias");
                fail("Was able to export CA keystore with null password!");
            } catch (Exception e) {
                // NOPMD it's ok to throw e.g. NPE
            }
            
            try {
                caadminsession.exportCAKeyStore(internalAdmin, caname, "", "", "SignatureKeyAlias", "EncryptionKeyAlias");
                fail("Was able to export CA keystore with empty password!");
            } catch (Exception e) {
                // NOPMD
            }
        } finally {
            caSession.removeCA(internalAdmin, cainfo.getCAId());
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
        log.trace("<test08ExportWithPassword()");
    }
    
    /** Tests export of a CA with a CryptoToken without a password (strictly speaking, with a default password) */
    @Test
    public void test09ExportWithNoPassword() throws Exception {
        final String caname = "test09";
        log.trace("<test09ExportWithNoPassword..()");
        
        // Create a crypto token with no password (i.e. a default one is used)
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        final int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(internalAdmin, caname, SoftCryptoToken.class.getName(), cryptoTokenProperties, null, null);
        cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
        cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
        try {
            // Create CA
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            cainfo = getNewCAInfo(caname, catoken);
            try {
                caSession.removeCA(internalAdmin, cainfo.getCAId());
            } catch (Exception e) { 
                // NOPMD
            }
            caadminsession.createCA(internalAdmin, cainfo);
            
            // Export it. This should not work since we don't allow to export an unprotected crypto token (even if it has the default password).
            try {
                caadminsession.exportCAKeyStore(internalAdmin, caname, "", "", "SignatureKeyAlias", "EncryptionKeyAlias");
                fail("exporting CA keystore with no password should not be allowed.");
            } catch (Exception e) {} // NOPMD: we just want to make sure it fails
        } finally {
            caSession.removeCA(internalAdmin, cainfo.getCAId());
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        }
        log.trace("<test09ExportWithNoPassword()");
    }
    
    /**
     * Creates a CAinfo for testing.
     *  
     * @param caname The name this CA-info will be assigned
     * @param catoken The tokeninfo for this CA-info
     * @return The new X509CAInfo for testing.
     */
	private X509CAInfo getNewCAInfo(String caname, CAToken catoken) {
        cainfo = new X509CAInfo("CN="+caname, caname, CAConstants.CA_ACTIVE, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("Used for testing CA import and export");
        cainfo.setExpireTime(new Date(System.currentTimeMillis()+364*24*3600*1000));
        cainfo.setDeltaCRLPeriod(0 * SimpleTime.MILLISECONDS_PER_HOUR);
		return cainfo;
	}

    /**
     * Perform test of import and export with interal admin.

     * @param catokeninfo The tokeninfo for this CA-info
     */
	private void subTest(CAToken catoken) throws Exception {
	    byte[] keystorebytes = null;
	    String caname = "DummyTestCA";
	    String keyFingerPrint = null;
	    cainfo = getNewCAInfo(caname, catoken);
	    try  {
	        try {
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	        } catch (Exception e) { 
	            // NOPMD:			
	        }
	        try {
	            caadminsession.createCA(internalAdmin, cainfo);
	        } catch (Exception e) {
	            log.info("Error: ", e);
	            fail("Could not create CA \"" + caname + "\" for testing." + e);
	        }
	        try {
	            keyFingerPrint = catestsession.getKeyFingerPrint(caname);
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	            fail("Could not get key fingerprint for \"" + caname + "\"." + e);
	        }
	        try {
	            keystorebytes = caadminsession.exportCAKeyStore(internalAdmin, caname, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	            fail("Could not export CA. " + e);
	        }
	        try {
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	            fail("Could not remove CA. " + e);
	        }
	        int crlNumberBefore = crlStore.getLastCRLNumber(cainfo.getSubjectDN(), false);
	        try {
	            caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	            fail("Could not import CA. " + e);
	        }
            assertTrue("Fingerprint does not match for \"" + caname + "\".", keyFingerPrint.equals(catestsession.getKeyFingerPrint(caname)));
	        int crlNumberAfter= crlStore.getLastCRLNumber(cainfo.getSubjectDN(), false);
	        assertEquals("CRL number of CRL generated on import should be 1 higher than any pre-existing CRLs.", crlNumberBefore+1, crlNumberAfter);

	        try {
	            final int cryptoTokenId = caSession.getCAInfo(internalAdmin, cainfo.getCAId()).getCAToken().getCryptoTokenId();
	            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	        } catch (Exception e) { 
	            log.info(e);
	            fail("Could not remove CA." + e);
	        }
	    } finally {
	        // remove all certificate and CRLs generated...  
	        internalCertificateStoreSession.removeCertificatesBySubject(cainfo.getSubjectDN());
	        byte[] crlBytes = null;
	        do {
	            crlBytes = crlStore.getLastCRL(cainfo.getSubjectDN(), false);
	            if (crlBytes != null) {
	                internalCertificateStoreSession.removeCRL(internalAdmin, CertTools.getFingerprintAsString(crlBytes));
	            }
	        } while (crlBytes != null);
	    }
	}

    /**
     * Perform security test of import and export with specified admin. 
     *  
     * @param catokeninfo The tokeninfo for this CA-info
     * @param admin The unathorized administrator 
     */
	private void subTestPublicAccess(CAToken catoken, AuthenticationToken admin) throws Exception {
		byte[] keystorebytes = null;
        String caname = "DummyTestCA";
        String keyFingerPrint = null;
        cainfo = getNewCAInfo(caname, catoken);
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
		} catch (Exception e) { 
			// NOPMD:			
		}
		try {
			caadminsession.createCA(admin, cainfo);
			fail("Could create CA \"" + caname + "\".");
		} catch (Exception e) {
		    // NOPMD expected
		}
		try {
			caadminsession.createCA(internalAdmin, cainfo);
		} catch (Exception e) { 
			log.info("Error: ", e);
			fail("Could not create CA \"" + caname + "\" for testing. " + e);
		}
		try {
			keyFingerPrint = catestsession.getKeyFingerPrint(caname);
		} catch (Exception e) {
		    log.info("Error: ", e);
		    fail("Could not get key fingerprint for \"" + caname + "\". " + e);
		}
		try {
			keystorebytes = caadminsession.exportCAKeyStore(admin, caname, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
			fail("Could export CA.");
		} catch (Exception e) {
		    // NOPMD expected
		}
		try {
			keystorebytes = caadminsession.exportCAKeyStore(internalAdmin, caname, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
		} catch (Exception e) { 
			log.info("Error: ", e);
			fail("Could not export CA. " + e);
		}
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
		} catch (Exception e) { 
			log.info("Error: ", e);
		    fail("Could not remove CA." + e);
		}
		try {
			caadminsession.importCAFromKeyStore(admin, caname, keystorebytes, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
			fail("Could import CA.");
		} catch (Exception e) {
		    // NOPMD expected
		}
		try {
			caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, TEST_PASSWORD, TEST_PASSWORD, "SignatureKeyAlias", "EncryptionKeyAlias");
		} catch (Exception e) { 
			log.info("Error: ", e);
			fail("Could not import CA. " + e);
		}
		assertTrue("Fingerprint does not match for \"" + caname + "\".", keyFingerPrint.equals(catestsession.getKeyFingerPrint(caname)));
		try {
            final int cryptoTokenId = caSession.getCAInfo(internalAdmin, caname).getCAToken().getCryptoTokenId();
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
		} catch (Exception e) { 
			log.info("Error: ", e);
		    fail("Could not remove CA. " + e);
		}
	}
}
