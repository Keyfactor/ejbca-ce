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

import javax.naming.Context;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Tests CA import and export.
 */
public class TestCAImportExport extends TestCase  {
    private static Logger log = Logger.getLogger(TestCAImportExport.class);
    private static Context ctx;
    private static ICAAdminSessionRemote caadminsession;
    private static X509CAInfo cainfo = null;

    /**
     * Creates a new TestCAImportExport object.
     *
     * @param name name
     */
    public TestCAImportExport(String name) {
        super(name);
    }
    
    /**
     * Setup test enviroment.
     *
     * @throws Exception
     */
    protected void setUp() throws Exception {
        log.debug(">setUp()");
		ctx = org.ejbca.core.ejb.InitialContextBuilder.getInstance().getInitialContext();
		ICAAdminSessionHome home = (org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"), org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome.class );            
		caadminsession = home.create();          
		log.debug("<setUp()");
    }
    
    /**
     * Tear down test enviroment. Does nothing.
     *
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    }
    
    /**
     * Tries to export and import a CA that is using SHA1withRSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test01ImportExportSHA1withRSA() throws Exception {
	    log.debug("<test01ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("2048");
        catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.debug("<test01ImportExport()");
	} // test01ImportExport

    /**
     * Tries to export and import a CA that is using SHA1withECDSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test02ImportExportSHA1withECDSA() throws Exception {
	    log.debug("<test02ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(CATokenConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.debug("<test02ImportExport()");
	} // test02ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test03ImportExportSHA256withRSA() throws Exception {
	    log.debug("<test03ImportExport..()");
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA256_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("2048");
        catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.debug("<test03ImportExport()");
	} // test03ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withECDSA as signature algorithm.
     *
     * @throws Exception
     */
	public void test04ImportExportSHA256withECDSA() throws Exception {
	    log.debug("<test04ImportExport..()");
	    CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA256_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(CATokenConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
        subTest(catokeninfo);
	    log.debug("<test04ImportExport()");
	} // test04ImportExport

    /**
     * Tries to export and import a CA that is using SHA256withRSA as signature algorithm and assuming
     * the admin role of a "Public web user". This method tests that the accessrules are working for 
     * and the test will succeed if the commands fail.
     *
     * @throws Exception
     */
	public void test05ImportExportAccess() throws Exception {
	    log.debug("<test05ImportExport..()");
	    CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA256_WITH_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(CATokenConstants.KEYALGORITHM_ECDSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("prime192v1");
        catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(CATokenConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("2048");
		subTestPublicAccess(catokeninfo, new Admin(Admin.TYPE_PUBLIC_WEB_USER));
	    log.debug("<test05ImportExport()");
	} // test05ImportExport

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
                new ArrayList(), // PolicyId
                24, // CRLPeriod
                0, // CRLIssuePeriod
                10, // CRLOverlapTime
                0, //DeltaCRLOverlapTime                
                new ArrayList(),
                true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                "", // Default CRL Dist Point
                "", // Default CRL Issuer
                "", // Default OCSP Service Locator  
                null, // defaultfreshestcrl
                true, // Finish User
                new ArrayList(), //extendedcaservices
                false, // use default utf8 settings
                new ArrayList(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false,  // CRL Distribution Point on CRL critical
                true // include in health check
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
			caadminsession.removeCA(admin, cainfo.getCAId());
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
			caadminsession.removeCA(admin, cainfo.getCAId());
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
			caadminsession.removeCA(admin, cainfo.getCAId());
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
			caadminsession.removeCA(internalAdmin, cainfo.getCAId());
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
		} catch (Exception e) { }
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
			caadminsession.removeCA(internalAdmin, cainfo.getCAId());
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
			caadminsession.removeCA(internalAdmin, cainfo.getCAId());
			ret = true;
		} catch (Exception e) { }
		assertTrue("Could not remove CA.", ret);
	}
}
