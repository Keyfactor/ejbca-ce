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

package org.ejbca.core.model.ca.certificateprofiles;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * Tests the certificate profile entity bean.
 *
 * @version $Id$
 */
public class CertificateProfileTest extends TestCase {
    private static final Logger log = Logger.getLogger(CertificateProfileTest.class);

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    
    /**
     * Creates a new TestCertificateProfile object.
     *
     * @param name name
     */
    public CertificateProfileTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * adds a profile to the database
     *
     * @throws Exception error
     */
    public void test01AddCertificateProfile() throws Exception {
        log.trace(">test01AddCertificateProfile()");
        boolean ret = false;
        try {
            CertificateProfile profile = new CertificateProfile();
            profile.setCRLDistributionPointURI("TEST");
            certificateStoreSession.addCertificateProfile(admin, "TEST", profile);
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }

        assertTrue("Creating Certificate Profile failed", ret);
        log.trace("<test01AddCertificateProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameCertificateProfile() throws Exception {
        log.trace(">test02RenameCertificateProfile()");

        boolean ret = false;
        try {
            certificateStoreSession.renameCertificateProfile(admin, "TEST", "TEST2");
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }
        assertTrue("Renaming Certificate Profile failed", ret);

        log.trace("<test02RenameCertificateProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneCertificateProfile() throws Exception {
        log.trace(">test03CloneCertificateProfile()");
        boolean ret = false;
        try {
            certificateStoreSession.cloneCertificateProfile(admin, "TEST2", "TEST", caAdminSessionRemote.getAvailableCAs(admin));
            ret = true;
        } catch (CertificateProfileExistsException pee) {
        }
        assertTrue("Cloning Certificate Profile failed", ret);
        log.trace("<test03CloneCertificateProfile()");
    }


    /**
     * edits profile
     *
     * @throws Exception error
     */
    public void test04EditCertificateProfile() throws Exception {
        log.trace(">test04EditCertificateProfile()");

        boolean ret = false;

        CertificateProfile profile = certificateStoreSession.getCertificateProfile(admin, "TEST");
        assertTrue("Retrieving CertificateProfile failed", profile.getCRLDistributionPointURI().equals("TEST"));

        profile.setCRLDistributionPointURI("TEST2");

        certificateStoreSession.changeCertificateProfile(admin, "TEST", profile);
        ret = true;

        assertTrue("Editing CertificateProfile failed", ret);


        log.trace("<test04EditCertificateProfile()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeCertificateProfiles() throws Exception {
        log.trace(">test05removeCertificateProfiles()");
        boolean ret = false;
        try {
            certificateStoreSession.removeCertificateProfile(admin, "TEST");
            certificateStoreSession.removeCertificateProfile(admin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Certificate Profile failed", ret);

        log.trace("<test05removeCertificateProfiles()");
    }
    
    public void test06createSubjectDNSubSet() throws Exception{
        log.trace(">test06createSubjectDNSubSet()");    	
    	CertificateProfile profile = new CertificateProfile();
    	
    	ArrayList<Integer> dnsubset = new ArrayList<Integer>();
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
        
        log.trace(">test06createSubjectDNSubSet()");
    }

    public void test07createSubjectAltNameSubSet() throws Exception{
        log.trace(">test07createSubjectAltNameSubSet()");

    	CertificateProfile profile = new CertificateProfile();
    	
    	ArrayList<Integer> altnamesubset = new ArrayList<Integer>();
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
        
        log.trace(">test07createSubjectAltNameSubSet()");
    }
    
    public void test08CertificateProfileValues() throws Exception {
        CertificateProfile ep = new EndUserCertificateProfile();
        List<CertificatePolicy> l = ep.getCertificatePolicies();
        assertEquals(0, l.size());
        ep.addCertificatePolicy(new CertificatePolicy(CertificatePolicy.ANY_POLICY_OID, null, null));
        l = ep.getCertificatePolicies();
        assertEquals(1, l.size());
        CertificatePolicy pol = (CertificatePolicy)l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID() );
        assertEquals(CertificateProfile.LATEST_VERSION, ep.getLatestVersion(),0);
        String qcId = ep.getQCSemanticsId();
        assertEquals("", qcId);
        CertificateProfile cp = new CertificateProfile();
        l = cp.getCertificatePolicies();
        assertEquals(0, l.size());
        cp.addCertificatePolicy(new CertificatePolicy(CertificatePolicy.ANY_POLICY_OID, null, null));
        l = cp.getCertificatePolicies();
        assertEquals(1, l.size());
        pol = (CertificatePolicy)l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID());
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.1.1", null, null));
        l = cp.getCertificatePolicies();
        assertEquals(2, l.size());
        pol = (CertificatePolicy)l.get(0);
        assertEquals("2.5.29.32.0", pol.getPolicyID());
        pol = (CertificatePolicy)l.get(1);
        assertEquals("1.1.1.1.1", pol.getPolicyID());
        assertEquals(CertificateProfile.LATEST_VERSION, cp.getLatestVersion(),0);
        assertEquals("", cp.getQCSemanticsId());
        cp.setQCSemanticsId("1.1.1.2");
        assertEquals("1.1.1.2", cp.getQCSemanticsId());
        
        assertNull(cp.getSignatureAlgorithm()); // default value null = inherit from CA
        cp.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, cp.getSignatureAlgorithm());
    } // test08CertificateProfileValues

    public void test09CertificateExtensions() throws Exception{
        log.trace(">test09CertificateExtensions()");

    	CertificateProfile profile = new CertificateProfile();
    	
    	// Check standard values for the certificate profile
    	List l = profile.getUsedStandardCertificateExtensions();
    	assertEquals(l.size(), 5);
    	assertTrue(l.contains(X509Extensions.KeyUsage.getId()));
    	assertTrue(l.contains(X509Extensions.BasicConstraints.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.AuthorityKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectAlternativeName.getId()));

    	CertificateProfile eprofile = new EndUserCertificateProfile();
    	
    	// Check standard values for the certificate profile
    	l = eprofile.getUsedStandardCertificateExtensions();
    	assertEquals(l.size(), 6);
    	assertTrue(l.contains(X509Extensions.KeyUsage.getId()));
    	assertTrue(l.contains(X509Extensions.BasicConstraints.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.AuthorityKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectAlternativeName.getId()));
    	assertTrue(l.contains(X509Extensions.ExtendedKeyUsage.getId()));

    	profile = new CertificateProfile();
    	profile.setUseAuthorityInformationAccess(true);
    	profile.setUseCertificatePolicies(true);
    	profile.setUseCRLDistributionPoint(true);
    	profile.setUseFreshestCRL(true);
    	profile.setUseMicrosoftTemplate(true);
    	profile.setUseOcspNoCheck(true);
    	profile.setUseQCStatement(true);
    	profile.setUseExtendedKeyUsage(true);
    	profile.setUseSubjectDirAttributes(true);
    	l = profile.getUsedStandardCertificateExtensions();
    	assertEquals(l.size(), 14);
    	assertTrue(l.contains(X509Extensions.KeyUsage.getId()));
    	assertTrue(l.contains(X509Extensions.BasicConstraints.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.AuthorityKeyIdentifier.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectAlternativeName.getId()));
    	assertTrue(l.contains(X509Extensions.ExtendedKeyUsage.getId()));
    	assertTrue(l.contains(X509Extensions.AuthorityInfoAccess.getId()));
    	assertTrue(l.contains(X509Extensions.CertificatePolicies.getId()));
    	assertTrue(l.contains(X509Extensions.CRLDistributionPoints.getId()));
    	assertTrue(l.contains(X509Extensions.FreshestCRL.getId()));
    	assertTrue(l.contains(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
    	assertTrue(l.contains(X509Extensions.QCStatements.getId()));
    	assertTrue(l.contains(X509Extensions.SubjectDirectoryAttributes.getId()));
    	assertTrue(l.contains(CertTools.OID_MSTEMPLATE));
    	
    } // test09CertificateExtensions

    public void test10UpgradeExtendedKeyUsage() throws Exception {
        CertificateProfile ep = new EndUserCertificateProfile();
        assertEquals(CertificateProfile.LATEST_VERSION, ep.getLatestVersion(),0);
        ep.setVersion((float)31.0);
        ArrayList eku = new ArrayList();
        eku.add(Integer.valueOf(1));
        eku.add(Integer.valueOf(2));
        eku.add(Integer.valueOf(3));
        ep.setExtendedKeyUsage(eku);
        ArrayList ar = ep.getExtendedKeyUsageArray();
        Object o = ar.get(0);
        assertTrue((o instanceof Integer));
        assertEquals(3, ar.size());

        ar = ep.getExtendedKeyUsageOids();
        o = ar.get(0);
        assertTrue((o instanceof String));
        assertEquals(3, ar.size());

        ep.upgrade();
        ar = ep.getExtendedKeyUsageArray();
        o = ar.get(0);
        assertTrue((o instanceof String));
        assertEquals(3, ar.size());
        assertEquals("1.3.6.1.5.5.7.3.1", ar.get(0));
        assertEquals("1.3.6.1.5.5.7.3.2", ar.get(1));
        assertEquals("1.3.6.1.5.5.7.3.3", ar.get(2));
        
    } // test10UpgradeExtendedKeyUsage

    public void test11CertificateProfileMappings() throws Exception {
    	certificateStoreSession.removeCertificateProfile(admin, "TESTCPMAPPINGS1");
    	certificateStoreSession.removeCertificateProfile(admin, "TESTCPMAPPINGS2");
    	// Add a couple of profiles and verify that the mappings and get functions work
    	EndUserCertificateProfile ecp1 = new EndUserCertificateProfile();
    	ecp1.setCNPostfix("foo");
    	certificateStoreSession.addCertificateProfile(admin, "TESTCPMAPPINGS1", ecp1);
    	EndUserCertificateProfile ecp2 = new EndUserCertificateProfile();
    	ecp2.setCNPostfix("bar");
    	certificateStoreSession.addCertificateProfile(admin, "TESTCPMAPPINGS2", ecp2);
    	// Test
        int pid1 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS1"); 
        String name1 = certificateStoreSession.getCertificateProfileName(admin, pid1);
        assertEquals("TESTCPMAPPINGS1", name1);
        int pid2 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS1"); 
        String name2 = certificateStoreSession.getCertificateProfileName(admin, pid2);
        assertEquals("TESTCPMAPPINGS1", name2);
        assertEquals(pid1, pid2);
        assertEquals(name1, name2);
        log.debug(pid1);

        CertificateProfile profile = certificateStoreSession.getCertificateProfile(admin, pid1);
        assertEquals("foo", profile.getCNPostfix());
        profile = certificateStoreSession.getCertificateProfile(admin, name1);
        assertEquals("foo", profile.getCNPostfix());

        int pid3 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS2"); 
        log.debug(pid3);
        String name3 = certificateStoreSession.getCertificateProfileName(admin, pid3);
        assertEquals("TESTCPMAPPINGS2", name3);
        profile = certificateStoreSession.getCertificateProfile(admin, pid3);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateStoreSession.getCertificateProfile(admin, name3);
        assertEquals("bar", profile.getCNPostfix());

        // flush caches and make sure it is read correctly again
        certificateStoreSession.flushProfileCache();
    	
        int pid4 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS1"); 
        String name4 = certificateStoreSession.getCertificateProfileName(admin, pid4);
        assertEquals(pid1, pid4);
        assertEquals(name1, name4);
        profile = certificateStoreSession.getCertificateProfile(admin, pid4);
        assertEquals("foo", profile.getCNPostfix());
        profile = certificateStoreSession.getCertificateProfile(admin, name4);
        assertEquals("foo", profile.getCNPostfix());

        int pid5 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS2"); 
        String name5 = certificateStoreSession.getCertificateProfileName(admin, pid5);
        assertEquals(pid3, pid5);
        assertEquals(name3, name5);
        profile = certificateStoreSession.getCertificateProfile(admin, pid5);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateStoreSession.getCertificateProfile(admin, name5);
        assertEquals("bar", profile.getCNPostfix());

        // Remove a profile and make sure it is not cached still
        certificateStoreSession.removeCertificateProfile(admin, "TESTCPMAPPINGS1");
        profile = certificateStoreSession.getCertificateProfile(admin, pid1);
        assertNull(profile);
        profile = certificateStoreSession.getCertificateProfile(admin, "TESTCPMAPPINGS1");
        assertNull(profile);
        int pid6 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS1");
        assertEquals(0, pid6);
        String name6 = certificateStoreSession.getCertificateProfileName(admin, pid6);
        assertNull(name6);

        // But the other, non-removed profile should still be there
        int pid7 = certificateStoreSession.getCertificateProfileId(admin, "TESTCPMAPPINGS2"); 
        String name7 = certificateStoreSession.getCertificateProfileName(admin, pid7);
        assertEquals(pid3, pid7);
        assertEquals(name3, name7);
        profile = certificateStoreSession.getCertificateProfile(admin, pid7);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateStoreSession.getCertificateProfile(admin, name7);
        assertEquals("bar", profile.getCNPostfix());

        // Also check a few standard mappings
        assertEquals(SecConst.CERTPROFILE_FIXED_ENDUSER, certificateStoreSession.getCertificateProfileId(admin, EndUserCertificateProfile.CERTIFICATEPROFILENAME));
        assertEquals(SecConst.CERTPROFILE_FIXED_SERVER, certificateStoreSession.getCertificateProfileId(admin, ServerCertificateProfile.CERTIFICATEPROFILENAME));
        assertEquals(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN, certificateStoreSession.getCertificateProfileId(admin, HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME));

        assertEquals(EndUserCertificateProfile.CERTIFICATEPROFILENAME, certificateStoreSession.getCertificateProfileName(admin, SecConst.CERTPROFILE_FIXED_ENDUSER));
        assertEquals(ServerCertificateProfile.CERTIFICATEPROFILENAME, certificateStoreSession.getCertificateProfileName(admin, SecConst.CERTPROFILE_FIXED_SERVER));
        assertEquals(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME, certificateStoreSession.getCertificateProfileName(admin, SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
        assertEquals(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME, certificateStoreSession.getCertificateProfileName(admin, SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));

        certificateStoreSession.removeCertificateProfile(admin, "TESTCPMAPPINGS1");
    	certificateStoreSession.removeCertificateProfile(admin, "TESTCPMAPPINGS2");
    } // test11CertificateProfileMappings

    /**
     * Test of the cache of certificate profiles. This test depends on the default cache time of 1 second being used.
     * If you changed this config, eeprofiles.cachetime, this test may fail. 
     */
    public void test12CertificateProfileCache() throws Exception {
    	// First a check that we have the correct configuration, i.e. default
    	long cachetime = EjbcaConfiguration.getCacheCertificateProfileTime();
    	assertEquals(1000, cachetime);

    	// Add a profile
    	certificateStoreSession.removeCertificateProfile(admin, "TESTCPCACHE1");
    	EndUserCertificateProfile ecp1 = new EndUserCertificateProfile();
        ecp1.setCNPostfix("foo");
    	certificateStoreSession.addCertificateProfile(admin, "TESTCPCACHE1", ecp1);
    	
    	// Make sure profile has the right value from the beginning
        CertificateProfile ecp = certificateStoreSession.getCertificateProfile(admin, "TESTCPCACHE1");
        assertEquals("foo", ecp.getCNPostfix());
        ecp.setCNPostfix("bar");
        certificateStoreSession.changeCertificateProfile(admin, "TESTCPCACHE1", ecp);
    	// Read profile
        ecp = certificateStoreSession.getCertificateProfile(admin, "TESTCPCACHE1");
        assertEquals("bar", ecp.getCNPostfix());

        // Flush caches to reset cache timeout
        certificateStoreSession.flushProfileCache();
    	// Change profile, not flushing cache
        ecp.setCNPostfix("bar2000");
    	certificateStoreSession.internalChangeCertificateProfileNoFlushCache(admin, "TESTCPCACHE1", ecp);
    	// read profile again, value should not be changed because it is cached
        ecp = certificateStoreSession.getCertificateProfile(admin, "TESTCPCACHE1");
        assertEquals("bar", ecp.getCNPostfix());
    	
    	// Wait 2 seconds and try again, now the cache should have been updated
    	Thread.sleep(2000);
        ecp = certificateStoreSession.getCertificateProfile(admin, "TESTCPCACHE1");
        assertEquals("bar2000", ecp.getCNPostfix());

        // Changing using the regular method however should immediately flush the cache
        ecp.setCNPostfix("barfoo");
    	certificateStoreSession.changeCertificateProfile(admin, "TESTCPCACHE1", ecp);
        ecp = certificateStoreSession.getCertificateProfile(admin, "TESTCPCACHE1");
        assertEquals("barfoo", ecp.getCNPostfix());
        
    	certificateStoreSession.removeCertificateProfile(admin, "TESTCPCACHE1");

    } // test12CertificateProfileCache

}
