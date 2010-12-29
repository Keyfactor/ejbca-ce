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

import java.util.ArrayList;
import java.util.Date;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.InterfaceCache;

/**
 * Tests CA import and export.
 * 
 * @version $Id$
 */
public class CAImportExportTest extends TestCase  {
    private static Logger log = Logger.getLogger(CAImportExportTest.class);
    private static X509CAInfo cainfo = null;
    
    private CAAdminSessionRemote caadminsession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();

    /**
     * Creates a new TestCAImportExport object.
     *
     * @param name name
     */
    public CAImportExportTest(String name) {
        super(name);
    }
    
    /**
     * Setup test environment.
     *
     * @throws Exception
     */
    public void setUp() throws Exception {
    }
    
    /**
     * Tear down test environment. Does nothing.
     *
     * @throws Exception
     */
    public void tearDown() throws Exception {
    }
    
    /**
     * Tries to export and import a CA that is using SHA1withRSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test01ImportExportSHA1withRSA() throws Exception {
	    log.trace("<test01ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("2048");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.trace("<test01ImportExport()");
	} // test01ImportExport

    /**
     * Tries to export and import a CA that is using SHA1withECDSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test02ImportExportSHA1withECDSA() throws Exception {
	    log.trace("<test02ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.trace("<test02ImportExport()");
	} // test02ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test03ImportExportSHA256withRSA() throws Exception {
	    log.trace("<test03ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("2048");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.trace("<test03ImportExport()");
	} // test03ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withECDSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test04ImportExportSHA256withECDSA() throws Exception {
	    log.trace("<test04ImportExport..()");
	    CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
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
	public void test05ImportExportAccess() throws Exception {
	    log.trace("<test05ImportExport..()");
	    CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
		subTestPublicAccess(catokeninfo, new Admin(Admin.TYPE_PUBLIC_WEB_USER));
	    log.trace("<test05ImportExport()");
	} // test05ImportExport
	
	/**
     * Tries to export and import a CA that is using SHA1withDSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test06ImportExportSHA1withDSA() throws Exception {
	    log.trace("<test06ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_DSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("1024");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
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
                -1, null, // revokationreason, revokationdate
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
    	Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    	boolean defaultRetValue = false;
        if ( admin.getAdminType() == Admin.TYPE_INTERNALUSER ) {
        	defaultRetValue = true;
        }
		try {
		    caSession.removeCA(admin, cainfo.getCAId());
		} catch (Exception e) { }
		boolean ret = false;
		try {
			caadminsession.createCA(admin, cainfo);
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not create CA \"" + caname + "\" for testing.", ret, defaultRetValue);
		ret = false;
		try {
			keyFingerPrint = caadminsession.getKeyFingerPrint(admin, caname);
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not get key fingerprint for \"" + caname + "\".", ret, defaultRetValue);
		ret = false;
		try {
			keystorebytes = caadminsession.exportCAKeyStore(admin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not export CA.", ret, defaultRetValue);
		ret = false;
		try {
		    caSession.removeCA(admin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not remove CA.", ret, defaultRetValue);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(admin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not import CA.", ret, defaultRetValue);
		ret = false;
		try {
			if ( keyFingerPrint.equals(caadminsession.getKeyFingerPrint(admin, caname)) ) {
				ret = true;
			}
		} catch (Exception e) { }
		assertEquals("Fingerprint does not match for \"" + caname + "\".", ret, defaultRetValue);
		ret = false;
		try {
		    caSession.removeCA(admin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { }
		assertEquals("Could not remove CA.", ret, defaultRetValue);
	}

    /**
     * Perform security test of import and export with specified admin. 
     *  
     * @param catokeninfo The tokeninfo for this CA-info
     * @param admin The unathorized administrator 
     */
	private void subTestPublicAccess(CATokenInfo catokeninfo, Admin admin) throws Exception {
		byte[] keystorebytes = null;
        String caname = "DummyTestCA";
        String capassword = "foo123";
        String keyFingerPrint = null;
        cainfo = getNewCAInfo(caname, catokeninfo);
        Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
		} catch (Exception e) { }
		boolean ret = false;
		try {
			caadminsession.createCA(internalAdmin, cainfo);
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not create CA \"" + caname + "\" for testing.", ret);
		ret = false;
		try {
			keyFingerPrint = caadminsession.getKeyFingerPrint(admin, caname);
			ret = true;
		} catch (Exception e) {}
		assertFalse("Could get key fingerprint for \"" + caname + "\".", ret);
		ret = false;
		try {
			keyFingerPrint = caadminsession.getKeyFingerPrint(internalAdmin, caname);
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not get key fingerprint for \"" + caname + "\".", ret);
		ret = false;
		try {
			keystorebytes = caadminsession.exportCAKeyStore(admin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertFalse("Could export CA.", ret);
		ret = false;
		try {
			keystorebytes = caadminsession.exportCAKeyStore(internalAdmin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not export CA.", ret);
		ret = false;
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not remove CA.", ret);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(admin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertFalse("Could import CA.", ret);
		ret = false;
		try {
			caadminsession.importCAFromKeyStore(internalAdmin, caname, keystorebytes, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not import CA.", ret);
		ret = false;
		try {
			if ( keyFingerPrint.equals(caadminsession.getKeyFingerPrint(admin, caname)) ) {
				ret = true;
			}
		} catch (Exception e) { }
		assertFalse("Fingerprint does match for \"" + caname + "\".", ret);
		ret = false;
		try {
			if ( keyFingerPrint.equals(caadminsession.getKeyFingerPrint(internalAdmin, caname)) ) {
				ret = true;
			}
		} catch (Exception e) { }
		assertTrue("Fingerprint does not match for \"" + caname + "\".", ret);
		ret = false;
		try {
		    caSession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not remove CA.", ret);
	}
}
