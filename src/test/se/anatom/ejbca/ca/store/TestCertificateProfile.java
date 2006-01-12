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

package se.anatom.ejbca.ca.store;

import java.util.ArrayList;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.EndUserCertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;

/**
 * Tests the certificate profile entity bean.
 *
 * @version $Id: TestCertificateProfile.java,v 1.4 2006-01-12 08:58:44 anatom Exp $
 */
public class TestCertificateProfile extends TestCase {
    private static Logger log = Logger.getLogger(TestCertificateProfile.class);

    private static ICertificateStoreSessionRemote cacheAdmin;
    private static ICertificateStoreSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCertificateProfile object.
     *
     * @param name name
     */
    public TestCertificateProfile(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CertificateStoreSession");
                cacheHome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
            }
            cacheAdmin = cacheHome.create();
        }
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
     * adds a profile to the database
     *
     * @throws Exception error
     */
    public void test01AddCertificateProfile() throws Exception {
        log.debug(">test01AddCertificateProfile()");
        boolean ret = false;
        try {
            CertificateProfile profile = new CertificateProfile();
            profile.setCRLDistributionPointURI("TEST");
            cacheAdmin.addCertificateProfile(admin, "TEST", profile);
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }

        assertTrue("Creating Certificate Profile failed", ret);
        log.debug("<test01AddCertificateProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameCertificateProfile() throws Exception {
        log.debug(">test02RenameCertificateProfile()");

        boolean ret = false;
        try {
            cacheAdmin.renameCertificateProfile(admin, "TEST", "TEST2");
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }
        assertTrue("Renaming Certificate Profile failed", ret);

        log.debug("<test02RenameCertificateProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneCertificateProfile() throws Exception {
        log.debug(">test03CloneCertificateProfile()");
        boolean ret = false;
        try {
            cacheAdmin.cloneCertificateProfile(admin, "TEST2", "TEST");
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }
        assertTrue("Cloning Certificate Profile failed", ret);
        log.debug("<test03CloneCertificateProfile()");
    }


    /**
     * edits profile
     *
     * @throws Exception error
     */
    public void test04EditCertificateProfile() throws Exception {
        log.debug(">test04EditCertificateProfile()");

        boolean ret = false;

        CertificateProfile profile = cacheAdmin.getCertificateProfile(admin, "TEST");
        assertTrue("Retrieving CertificateProfile failed", profile.getCRLDistributionPointURI().equals("TEST"));

        profile.setCRLDistributionPointURI("TEST2");

        cacheAdmin.changeCertificateProfile(admin, "TEST", profile);
        ret = true;

        assertTrue("Editing CertificateProfile failed", ret);


        log.debug("<test04EditCertificateProfile()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeCertificateProfiles() throws Exception {
        log.debug(">test05removeCertificateProfiles()");
        boolean ret = false;
        try {
            cacheAdmin.removeCertificateProfile(admin, "TEST");
            cacheAdmin.removeCertificateProfile(admin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Certificate Profile failed", ret);

        log.debug("<test05removeCertificateProfiles()");
    }
    
    public void test06createSubjectDNSubSet() throws Exception{
        log.debug(">test06createSubjectDNSubSet()");    	
    	CertificateProfile profile = new CertificateProfile();
    	
    	ArrayList dnsubset = new ArrayList();
    	dnsubset.add(new Integer(DNFieldExtractor.CN));
    	dnsubset.add(new Integer(DNFieldExtractor.UID));
    	dnsubset.add(new Integer(DNFieldExtractor.GIVENNAME));
    	dnsubset.add(new Integer(DNFieldExtractor.SURNAME));    	
    	profile.setSubjectDNSubSet(dnsubset);
    	
    	String indn1 = "UID=PVE,CN=Philip Vendil,SN=123435,GIVENNAME=Philip,SURNAME=Vendil";
    	String outdn1 = profile.createSubjectDNSubSet(indn1);
    	String expecteddn1 = "UID=PVE,CN=Philip Vendil,GIVENNAME=Philip,SURNAME=Vendil";
        assertTrue("createSubjectDNSubSet doesn't work" + outdn1 + " != "+ expecteddn1, expecteddn1.equalsIgnoreCase(outdn1)); 
        
    	String indn2 = "UID=PVE,CN=Philip Vendil,CN=SecondUsername,SN=123435,SN=54321,GIVENNAME=Philip,SURNAME=Vendil";
    	String outdn2 = profile.createSubjectDNSubSet(indn2);
    	String expecteddn2 = "UID=PVE,CN=Philip Vendil,CN=SecondUsername,GIVENNAME=Philip,SURNAME=Vendil";
        assertTrue("createSubjectDNSubSet doesn't work" + outdn2 + " != "+ expecteddn2, expecteddn2.equalsIgnoreCase(outdn2));
        
        log.debug(">test06createSubjectDNSubSet()");
    }

    public void test07createSubjectAltNameSubSet() throws Exception{
        log.debug(">test07createSubjectAltNameSubSet()");

    	CertificateProfile profile = new CertificateProfile();
    	
    	ArrayList altnamesubset = new ArrayList();
    	altnamesubset.add(new Integer(DNFieldExtractor.RFC822NAME));
    	altnamesubset.add(new Integer(DNFieldExtractor.UPN));    	
    	profile.setSubjectAltNameSubSet(altnamesubset);
    	
    	String inaltname1 = "RFC822NAME=test@test.se,UPN=testacc@test.se,IPADDRESS=10.1.1.0";
    	String outaltname1 = profile.createSubjectAltNameSubSet(inaltname1);
    	String expectedaltname1 = "RFC822NAME=test@test.se,UPN=testacc@test.se";
        assertTrue("createSubjectAltNameSubSet doesn't work" + outaltname1 + " != "+ expectedaltname1, expectedaltname1.equalsIgnoreCase(outaltname1)); 
        
    	String inaltname2 = "RFC822NAME=test@test.se,RFC822NAME=test2@test2.se,UPN=testacc@test.se,IPADDRESS=10.1.1.0,IPADDRESS=10.1.1.2";
    	String outaltname2 = profile.createSubjectAltNameSubSet(inaltname2);
    	String expectedaltname2 = "RFC822NAME=test@test.se,RFC822NAME=test2@test2.se,UPN=testacc@test.se";
        assertTrue("createSubjectAltNameSubSet doesn't work" + outaltname2 + " != "+ expectedaltname2, expectedaltname2.equalsIgnoreCase(outaltname2));
        
        log.debug(">test07createSubjectAltNameSubSet()");
    }
    
    public void test08CertificateProfileValues() throws Exception {
        CertificateProfile ep = new EndUserCertificateProfile();
        assertEquals("2.5.29.32.0", ep.getCertificatePolicyId());
        assertEquals(CertificateProfile.LATEST_VERSION, ep.getLatestVersion(),0);
        String qcId = ep.getQCStatementId();
        assertEquals("", qcId);
        CertificateProfile cp = new CertificateProfile();
        assertEquals("2.5.29.32.0", cp.getCertificatePolicyId());
        assertEquals(CertificateProfile.LATEST_VERSION, cp.getLatestVersion(),0);
        assertEquals("", cp.getQCStatementId());
        cp.setQCStatementId("1.1.1.2");
        assertEquals("1.1.1.2", cp.getQCStatementId());
    }
}
