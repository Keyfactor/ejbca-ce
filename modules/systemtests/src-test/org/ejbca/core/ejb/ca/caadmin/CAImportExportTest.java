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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.InterfaceCache;
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
    
    private CAAdminSessionRemote caadminsession = InterfaceCache.getCAAdminSession();
    private CAAdminTestSessionRemote catestsession = JndiHelper.getRemoteSession(CAAdminTestSessionRemote.class);
    private CaSessionRemote caSession = InterfaceCache.getCaSession();

    private static AuthenticationToken adminTokenNoAuth;

    @BeforeClass
    public static void beforeTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, CertificateEncodingException, SignatureException, IllegalStateException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
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
    
    private CATokenInfo createCaTokenInfo(String sigAlg, String signKeySpec, String encAlg) {
    	CATokenInfo catokeninfo = new CATokenInfo();
    	catokeninfo.setSignatureAlgorithm(sigAlg);
    	catokeninfo.setEncryptionAlgorithm(encAlg);
    	catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
    	catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
    	catokeninfo.setClassPath(SoftCryptoToken.class.getName());
    	Properties prop = catokeninfo.getProperties();
    	// Set some CA token properties if they are not set already
    	if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
    		prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, signKeySpec);
    	}
    	if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
    		prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	}
    	if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
    		prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	}
    	if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
    		prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
    	}
    	catokeninfo.setProperties(prop);
    	return catokeninfo;
    }
    
    /**
     * Tries to export and import a CA that is using SHA1withRSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test01ImportExportSHA1withRSA() throws Exception {
	    log.trace("<test01ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        subTest(catokeninfo);
	    log.trace("<test01ImportExport()");
	} // test01ImportExport

    /**
     * Tries to export and import a CA that is using SHA1withECDSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test02ImportExportSHA1withECDSA() throws Exception {
	    log.trace("<test02ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA, "prime192v1", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        subTest(catokeninfo);
	    log.trace("<test02ImportExport()");
	} // test02ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test03ImportExportSHA256withRSA() throws Exception {
	    log.trace("<test03ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, "2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        subTest(catokeninfo);
	    log.trace("<test03ImportExport()");
	} // test03ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withECDSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test04ImportExportSHA256withECDSA() throws Exception {
	    log.trace("<test04ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, "prime192v1", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        subTest(catokeninfo);
	    log.trace("<test04ImportExport()");
	} // test04ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm and assuming
     * the admin role of a "Public web user". This method tests that the accessrules are working for 
     * and the test will succeed if the commands fail.
     *
     * @throws Exception
     */
    @Test
	public void test05ImportExportAccess() throws Exception {
	    log.trace("<test05ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, "prime192v1", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
		subTestPublicAccess(catokeninfo, adminTokenNoAuth);
	    log.trace("<test05ImportExport()");
	} // test05ImportExport
	
	/**
     * Tries to export and import a CA that is using SHA1withDSA as signature algorithm.
     *
     * @throws Exception
     */
    @Test
	public void test06ImportExportSHA1withDSA() throws Exception {
	    log.trace("<test06ImportExport..()");
        CATokenInfo catokeninfo = createCaTokenInfo(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, "1024", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        subTest(catokeninfo);
	    log.trace("<test06ImportExport()");
	} // test02ImportExport

    /**
     * Creates a CAinfo for testing.
     *  
     * @param caname The name this CA-info will be assigned
     * @param catokeninfo The tokeninfo for this CA-info
     * @return The new X509CAInfo for testing.
     */
	private X509CAInfo getNewCAInfo(String caname, CATokenInfo catokeninfo) {
        cainfo = new X509CAInfo("CN="+caname,
        		caname, SecConst.CA_ACTIVE, new Date(), 
                "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                365,
                new Date(System.currentTimeMillis()+364*24*3600*1000), // Expiretime
                CAInfo.CATYPE_X509,
                CAInfo.SELFSIGNED,
                null, // certificatechain
                catokeninfo,
                "Used for testing CA import and export",
                -1, // revocationReason
                null, //revocationDate
                new ArrayList<CertificatePolicy>(), // PolicyId
                24, // CRLPeriod
                0, // CRLIssuePeriod
                10, // CRLOverlapTime
                0, //DeltaCRLOverlapTime                
                new ArrayList<Integer>(), // crlpublishers
                true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                "", // Default CRL Dist Point
                "", // Default CRL Issuer
                "", // Default OCSP Service Locator  
                null, // defaultfreshestcrl
                true, // Finish User
                new ArrayList<ExtendedCAServiceInfo>(), //extendedcaservices
                false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false,  // CRL Distribution Point on CRL critical
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

    /**
     * Perform test of import and export with interal admin.

     * @param catokeninfo The tokeninfo for this CA-info
     */
	private void subTest(CATokenInfo catokeninfo) throws Exception {
		byte[] keystorebytes = null;
        String caname = "DummyTestCA";
        String capassword = "foo123";
        String keyFingerPrint = null;
        cainfo = getNewCAInfo(caname, catokeninfo);
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    	boolean defaultRetValue = true;

    	try {
		    caSession.removeCA(admin, cainfo.getCAId());
		} catch (Exception e) { 
			// NOPMD:			
		}
		boolean ret = false;
		try {
			caadminsession.createCA(admin, cainfo);
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
			keystorebytes = caadminsession.exportCAKeyStore(admin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { 
			log.info("Error: ", e);
		}
		assertEquals("Could not export CA.", ret, defaultRetValue);
		ret = false;
		try {
		    caSession.removeCA(admin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertEquals("Could not remove CA.", ret, defaultRetValue);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(admin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
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
		assertEquals("Fingerprint does not match for \"" + caname + "\".", ret, defaultRetValue);
		ret = false;
		try {
		    caSession.removeCA(admin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertEquals("Could not remove CA.", ret, defaultRetValue);
	}

    /**
     * Perform security test of import and export with specified admin. 
     *  
     * @param catokeninfo The tokeninfo for this CA-info
     * @param admin The unathorized administrator 
     */
	private void subTestPublicAccess(CATokenInfo catokeninfo, AuthenticationToken admin) throws Exception {
		byte[] keystorebytes = null;
        String caname = "DummyTestCA";
        String capassword = "foo123";
        String keyFingerPrint = null;
        cainfo = getNewCAInfo(caname, catokeninfo);
        AuthenticationToken internalAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
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
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { 
			// NOPMD:			
		}
		assertTrue("Could not remove CA.", ret);
	}
}
