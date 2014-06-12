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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

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
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.keys.token.CryptoTokenTestUtils;
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
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static AuthenticationToken adminTokenNoAuth;
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAImportExportTest"));

    @BeforeClass
    public static void beforeTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException, IOException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertProfileSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);
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
	    final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test01", "1024");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test02", "prime256v1");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test03", "2048");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test04", "prime256v1");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test05", "prime256v1");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test06", "DSA1024");
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
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, "test07", "1024");
        try {
            CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            byte[] keystorebytes = null;
            String caname = "DummyTestCA";
            String capassword = "foo123";
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
	    String capassword = "foo123";
	    String keyFingerPrint = null;
	    cainfo = getNewCAInfo(caname, catoken);
	    boolean defaultRetValue = true;
	    try  {
	        try {
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	        } catch (Exception e) { 
	            // NOPMD:			
	        }
	        boolean ret = false;
	        try {
	            caadminsession.createCA(internalAdmin, cainfo);
	            ret = true;
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	        }
	        assertEquals("Could not create CA \"" + caname + "\" for testing.", ret, defaultRetValue);
	        ret = false;
	        try {
	            keyFingerPrint = catestsession.getKeyFingerPrint(caname);
	            ret = true;
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	        }
	        assertEquals("Could not get key fingerprint for \"" + caname + "\".", ret, defaultRetValue);
	        ret = false;
	        try {
	            keystorebytes = caadminsession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
	            ret = true;
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	        }
	        assertEquals("Could not export CA.", ret, defaultRetValue);
	        ret = false;
	        try {
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	            ret = true;
	        } catch (Exception e) { 
	            // NOPMD:			
	        }
	        assertEquals("Could not remove CA.", ret, defaultRetValue);
	        ret = false;
	        int crlNumberBefore = crlStore.getLastCRLNumber(cainfo.getSubjectDN(), false);
	        try {
	            caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
	            ret = true;
	        } catch (Exception e) { 
	            log.info("Error: ", e);
	        }
	        assertEquals("Could not import CA.", ret, defaultRetValue);
	        ret = false;
	        try {
	            if ( keyFingerPrint.equals(catestsession.getKeyFingerPrint(caname)) ) {
	                ret = true;
	            }
	        } catch (Exception e) { 
	            // NOPMD:			
	        }
	        int crlNumberAfter= crlStore.getLastCRLNumber(cainfo.getSubjectDN(), false);
	        assertEquals("CRL number of CRL generated on import should be 1 higher than any pre-existing CRLs.", crlNumberBefore+1, crlNumberAfter);

	        assertEquals("Fingerprint does not match for \"" + caname + "\".", ret, defaultRetValue);
	        ret = false;
	        try {
	            final int cryptoTokenId = caSession.getCAInfo(internalAdmin, cainfo.getCAId()).getCAToken().getCryptoTokenId();
	            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
	            caSession.removeCA(internalAdmin, cainfo.getCAId());
	            ret = true;
	        } catch (Exception e) { 
	            // NOPMD:			
	        }
	        assertEquals("Could not remove CA.", ret, defaultRetValue);
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
        String capassword = "foo123";
        String keyFingerPrint = null;
        cainfo = getNewCAInfo(caname, catoken);
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
		} catch (Exception e) { 
			// NOPMD:			
		}
		boolean ret = false;
		try {
			caadminsession.createCA(admin, cainfo);
			ret = true;
		} catch (Exception e) { 
			// NOPMD
		}
		assertFalse("Could create CA \"" + caname + "\".", ret);
		ret = false;
		try {
			caadminsession.createCA(internalAdmin, cainfo);
			ret = true;
		} catch (Exception e) { 
			log.info("Error: ", e);
		}
		assertTrue("Could not create CA \"" + caname + "\" for testing.", ret);
		ret = false;
		try {
			keyFingerPrint = catestsession.getKeyFingerPrint(caname);
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertTrue("Could not get key fingerprint for \"" + caname + "\".", ret);
		ret = false;
		try {
			keystorebytes = caadminsession.exportCAKeyStore(admin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { 
			// NOPMD
		}
		assertFalse("Could export CA.", ret);
		ret = false;
		try {
			keystorebytes = caadminsession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { 
			log.info("Error: ", e);
		}
		assertTrue("Could not export CA.", ret);
		ret = false;
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertTrue("Could not remove CA.", ret);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(admin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { 
			// NOPMD
		}
		assertFalse("Could import CA.", ret);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { 
			log.info("Error: ", e);
		}
		assertTrue("Could not import CA.", ret);
		ret = false;
		try {
			if ( keyFingerPrint.equals(catestsession.getKeyFingerPrint(caname)) ) {
				ret = true;
			}
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertTrue("Fingerprint does not match for \"" + caname + "\".", ret);
		ret = false;
		try {
            final int cryptoTokenId = caSession.getCAInfo(internalAdmin, caname).getCAToken().getCryptoTokenId();
            CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertTrue("Could not remove CA.", ret);
	}
}
