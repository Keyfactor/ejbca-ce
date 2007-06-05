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

package se.anatom.ejbca.ca.caadmin;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * Tests the ca data entity bean.
 *
 * @version $Id: TestCAs.java,v 1.21 2007-06-05 13:32:57 anatom Exp $
 */
public class TestCAs extends TestCase {
    private static Logger log = Logger.getLogger(TestCAs.class);

    private static ICAAdminSessionRemote cacheAdmin;


    private static ICAAdminSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCAs object.
     *
     * @param name name
     */
    public TestCAs(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CAAdminSession");
                cacheHome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
            }

            cacheAdmin = cacheHome.create();
        }
        
        CertTools.installBCProvider();

        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }


    /**
     * adds a CA using RSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    public void test01AddRSACA() throws Exception {
        log.debug(">test01AddRSACA()");
        boolean ret = false;
        try {

            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, "CN=TEST".hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec("1024");
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + "CN=TEST",
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=XKMSCertificate, " + "CN=TEST",
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));


            X509CAInfo cainfo = new X509CAInfo("CN=TEST",
                    "TEST", SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit RSA CA",
                    -1, null,
                    null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false); // Use UTF8 subject DN by default


            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TEST");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TEST"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TEST"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
            	RSAPublicKey rsapk = (RSAPublicKey) pk;
				assertEquals(rsapk.getAlgorithm(), "RSA");
			} else {
				assertTrue("Public key is not EC", false);
			}

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA failed", ret);
        log.debug("<test01AddRSACA()");
    }

    /**
     * renames CA in database.
     *
     * @throws Exception error
     */
    public void test02RenameCA() throws Exception {
        log.debug(">test02RenameCA()");

        boolean ret = false;
        try {
            cacheAdmin.renameCA(admin, "TEST", "TEST2");
            cacheAdmin.renameCA(admin, "TEST2", "TEST");
            ret = true;
        } catch (CAExistsException cee) {
        }
        assertTrue("Renaming CA failed", ret);

        log.debug("<test02RenameCA()");
    }


    /**
     * edits ca and checks that it's stored correctly.
     *
     * @throws Exception error
     */
    public void test03EditCA() throws Exception {
        log.debug(">test03EditCA()");

        X509CAInfo info = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        info.setCRLPeriod(33);
        cacheAdmin.editCA(admin, info);
        X509CAInfo info2 = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        assertTrue("Editing CA failed", info2.getCRLPeriod() == 33);

        log.debug("<test03EditCA()");
    }

    /**
     * adds a CA Using ECDSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    public void test04AddECDSACA() throws Exception {
        log.debug(">test04AddECDSACA()");
        boolean ret = false;
        try {

            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, "CN=TESTECDSA".hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec("prime192v1");
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_ECDSA);
            catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA256_WITH_ECDSA);
            catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + "CN=TESTECDSA",
                    "",
                    "prime192v1",
                    CATokenConstants.KEYALGORITHM_ECDSA));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=XKMSSignerCertificate, " + "CN=TESTECDSA",
                    "",
                    "prime192v1",
                    CATokenConstants.KEYALGORITHM_ECDSA));


            X509CAInfo cainfo = new X509CAInfo("CN=TESTECDSA",
                    "TESTECDSA", SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit ECDSA CA",
                    -1, null,
                    "2.5.29.32.0", // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false); // Use UTF8 subject DN by default 


            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TESTECDSA");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTECDSA"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTECDSA"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
				JCEECPublicKey ecpk = (JCEECPublicKey) pk;
				assertEquals(ecpk.getAlgorithm(), "EC");
				org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
				assertNotNull("ImplicitlyCA must have null spec", spec);
			} else {
				assertTrue("Public key is not EC", false);
			}

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating ECDSA CA failed", ret);
        log.debug("<test04AddECDSACA()");
    }

    /**
     * adds a CA Using ECDSA 'implicitlyCA' keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    public void test05AddECDSAImplicitlyCACA() throws Exception {
        log.debug(">test05AddECDSAImplicitlyCACA()");
        boolean ret = false;
        try {

            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, "CN=TESTECDSAImplicitlyCA".hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec("implicitlyCA");
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_ECDSA);
            catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA256_WITH_ECDSA);
            catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + "CN=TESTECDSAImplicitlyCA",
                    "",
                    "prime192v1",
                    CATokenConstants.KEYALGORITHM_ECDSA));
            
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=XKMSCertificate, " + "CN=TESTECDSAImplicitlyCA",
                    "",
                    "prime192v1",
                    CATokenConstants.KEYALGORITHM_ECDSA));


            X509CAInfo cainfo = new X509CAInfo("CN=TESTECDSAImplicitlyCA",
                    "TESTECDSAImplicitlyCA", SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit ECDSA ImplicitlyCA CA",
                    -1, null,
                    "2.5.29.32.0", // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false); // Use UTF8 subject DN by default 


            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TESTECDSAImplicitlyCA");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTECDSAImplicitlyCA"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTECDSAImplicitlyCA"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
				JCEECPublicKey ecpk = (JCEECPublicKey) pk;
				assertEquals(ecpk.getAlgorithm(), "EC");
				org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
				assertNull("ImplicitlyCA must have null spec", spec);
				
			} else {
				assertTrue("Public key is not EC", false);
			}

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating ECDSA ImplicitlyCA CA failed", ret);
        log.debug("<test05AddECDSAImplicitlyCACA()");
    }

    /**
     * adds a CA using RSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    public void test06AddRSASha256WithMGF1CA() throws Exception {
        log.debug(">test06AddRSASha256WithMGF1CA()");
        boolean ret = false;
        try {
        	String cadn = "CN=TESTSha256WithMGF1";
            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, cadn.hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec("1024");
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA256_WITH_RSA_AND_MGF1);
            catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA256_WITH_RSA_AND_MGF1);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + cadn,
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=XKMSCertificate, " + cadn,
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));


            X509CAInfo cainfo = new X509CAInfo(cadn,
                    "TESTSha256WithMGF1", SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit RSA CA",
                    -1, null,
                    null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false); // Use UTF8 subject DN by default


            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TESTSha256WithMGF1");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals(cadn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(cadn));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
            	RSAPublicKey rsapk = (RSAPublicKey) pk;
				assertEquals(rsapk.getAlgorithm(), "RSA");
			} else {
				assertTrue("Public key is not RSA", false);
			}

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA failed", ret);
        log.debug("<test06AddRSASha256WithMGF1CA()");
    }

}