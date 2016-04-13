/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificateprofile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the certificate profile entity bean.
 * 
 * @version $Id$
 */
public class CertificateProfileSessionTest extends RoleUsingTestCase {
    private static final Logger log = Logger.getLogger(CertificateProfileSessionTest.class);

    private static KeyPair keys;

    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateProfileSessionTest"));
    
    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }
    
    @Before
    public void setUp() throws Exception{
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CertProfileSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CertProfileSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(alwaysAllowToken, role, accessRules);
    }
    
    @After
    public void tearDown() throws Exception {
    	tearDownRemoveRole();
    }

    /**
     * adds a profile to the database
     *
     * @throws Exception error
     */
    @Test
    public void test01AddCertificateProfile() throws Exception {
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
            profile.setCRLDistributionPointURI("TEST");
            int id = certificateProfileSession.addCertificateProfile(roleMgmgToken, "TEST", profile);
            int id1 = certificateProfileSession.getCertificateProfileId("TEST");
            assertEquals(id, id1);
        } catch (CertificateProfileExistsException pee) {
        	assertTrue("Should not throw", false);
        }
        
        // Try to add a certificate profile with specified id
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            int id = certificateProfileSession.addCertificateProfile(roleMgmgToken, 999999, "TEST3", profile);
            int id1 = certificateProfileSession.getCertificateProfileId("TEST3");
            assertEquals(id, id1);
        } catch (CertificateProfileExistsException pee) {
        	assertTrue("Should not throw", false);
        }
        // Try to add a certificate profile with same name
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certificateProfileSession.addCertificateProfile(roleMgmgToken, 9999998, "TEST3", profile);
        	assertTrue("Should not work", false);
        } catch (CertificateProfileExistsException pee) {
        }
        // Try to add a certificate profile with same id
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certificateProfileSession.addCertificateProfile(roleMgmgToken, 999999, "TEST4", profile);
        	assertTrue("Should not work", false);
        } catch (CertificateProfileExistsException pee) {
        }
        // Try to add a certificate profile with fixed name
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certificateProfileSession.addCertificateProfile(roleMgmgToken, CertificateProfile.ENDUSERPROFILENAME, profile);
        	assertTrue("Should not work", false);
        } catch (CertificateProfileExistsException pee) {
        }
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    @Test
    public void test02RenameCertificateProfile() throws Exception {
        try {
            certificateProfileSession.renameCertificateProfile(roleMgmgToken, "TEST", "TEST2");
            CertificateProfile cp = certificateProfileSession.getCertificateProfile("TEST2");
            assertNotNull(cp);
        } catch (CertificateProfileExistsException pee) {
        	assertTrue(pee.getMessage(), false);
        }
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    @Test
    public void test03CloneCertificateProfile() throws Exception {
        try {
            certificateProfileSession.cloneCertificateProfile(roleMgmgToken, "TEST2", "TEST", null);
        } catch (CertificateProfileExistsException pee) {
            fail("Cloning Certificate Profile failed");
        }
        // Try to clone to a fixed profile name
        try {
            certificateProfileSession.cloneCertificateProfile(roleMgmgToken, "TEST2", CertificateProfile.ENDUSERPROFILENAME, null);
            fail("Cloning Certificate Profile failed");
        } catch (CertificateProfileExistsException pee) {
        }
        // Try to clone a non existing profile
        try {
            certificateProfileSession.cloneCertificateProfile(roleMgmgToken, "TEST127547483448fff", "TEST6", null);
            fail("Cloning Certificate Profile failed");
        } catch (CertificateProfileDoesNotExistException pne) {
        }
    }


    /**
     * edits profile
     *
     * @throws Exception error
     */
    @Test
    public void test04EditCertificateProfile() throws Exception {
        log.trace(">test04EditCertificateProfile()");
        CertificateProfile profile = certificateProfileSession.getCertificateProfile("TEST");
        assertTrue("Retrieving CertificateProfile failed", profile.getCRLDistributionPointURI().equals("TEST"));
        profile.setCRLDistributionPointURI("TEST2");
        certificateProfileSession.changeCertificateProfile(roleMgmgToken, "TEST", profile);
        profile = certificateProfileSession.getCertificateProfile("TEST");
        assertEquals("TEST2", profile.getCRLDistributionPointURI());
        profile.setCRLDistributionPointURI(null);
        profile.setApprovalSettings(null);
        certificateProfileSession.changeCertificateProfile(roleMgmgToken, "TEST", profile);
        profile = certificateProfileSession.getCertificateProfile("TEST");
        assertEquals("", profile.getCRLDistributionPointURI());
        log.trace("<test04EditCertificateProfile()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    @Test
    public void test05removeCertificateProfiles() throws Exception {
        log.trace(">test05removeCertificateProfiles()");
        boolean ret = false;

        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST2");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST3");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST4");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST5");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST6");
        // Remove something that does not exist, should work (but does nothing)
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TEST127547474fff");
        ret = true;

        assertTrue("Removing Certificate Profile failed", ret);

        log.trace("<test05removeCertificateProfiles()");
    }
    
    @Test
    public void test06CertificateProfileMappings() throws Exception {
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS1");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS2");
    	// Add a couple of profiles and verify that the mappings and get functions work
    	CertificateProfile ecp1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	ecp1.setCNPostfix("foo");
    	certificateProfileSession.addCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS1", ecp1);
    	CertificateProfile ecp2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	ecp2.setCNPostfix("bar");
    	certificateProfileSession.addCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS2", ecp2);
    	// Test
        int pid1 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS1"); 
        String name1 = certificateProfileSession.getCertificateProfileName(pid1);
        assertEquals("TESTCPMAPPINGS1", name1);
        int pid2 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS1"); 
        String name2 = certificateProfileSession.getCertificateProfileName(pid2);
        assertEquals("TESTCPMAPPINGS1", name2);
        assertEquals(pid1, pid2);
        assertEquals(name1, name2);
        log.debug(pid1);

        CertificateProfile profile = certificateProfileSession.getCertificateProfile(pid1);
        assertEquals("foo", profile.getCNPostfix());
        profile = certificateProfileSession.getCertificateProfile(name1);
        assertEquals("foo", profile.getCNPostfix());

        int pid3 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS2"); 
        log.debug(pid3);
        String name3 = certificateProfileSession.getCertificateProfileName(pid3);
        assertEquals("TESTCPMAPPINGS2", name3);
        profile = certificateProfileSession.getCertificateProfile(pid3);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateProfileSession.getCertificateProfile(name3);
        assertEquals("bar", profile.getCNPostfix());

        // flush caches and make sure it is read correctly again
        certificateProfileSession.flushProfileCache();
    	
        int pid4 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS1"); 
        String name4 = certificateProfileSession.getCertificateProfileName(pid4);
        assertEquals(pid1, pid4);
        assertEquals(name1, name4);
        profile = certificateProfileSession.getCertificateProfile(pid4);
        assertEquals("foo", profile.getCNPostfix());
        profile = certificateProfileSession.getCertificateProfile(name4);
        assertEquals("foo", profile.getCNPostfix());

        int pid5 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS2"); 
        String name5 = certificateProfileSession.getCertificateProfileName(pid5);
        assertEquals(pid3, pid5);
        assertEquals(name3, name5);
        profile = certificateProfileSession.getCertificateProfile(pid5);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateProfileSession.getCertificateProfile(name5);
        assertEquals("bar", profile.getCNPostfix());

        // Remove a profile and make sure it is not cached still
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS1");
        profile = certificateProfileSession.getCertificateProfile(pid1);
        assertNull(profile);
        profile = certificateProfileSession.getCertificateProfile("TESTCPMAPPINGS1");
        assertNull(profile);
        int pid6 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS1");
        assertEquals(0, pid6);
        String name6 = certificateProfileSession.getCertificateProfileName(pid6);
        assertNull(name6);

        // But the other, non-removed profile should still be there
        int pid7 = certificateProfileSession.getCertificateProfileId("TESTCPMAPPINGS2"); 
        String name7 = certificateProfileSession.getCertificateProfileName(pid7);
        assertEquals(pid3, pid7);
        assertEquals(name3, name7);
        profile = certificateProfileSession.getCertificateProfile(pid7);
        assertEquals("bar", profile.getCNPostfix());
        profile = certificateProfileSession.getCertificateProfile(name7);
        assertEquals("bar", profile.getCNPostfix());

        // Also check a few standard mappings
        assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, certificateProfileSession.getCertificateProfileId(CertificateProfile.ENDUSERPROFILENAME));
        assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER, certificateProfileSession.getCertificateProfileId(CertificateProfile.SERVERPROFILENAME));
        assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN, certificateProfileSession.getCertificateProfileId(CertificateProfile.HARDTOKENSIGNPROFILENAME));

        assertEquals(CertificateProfile.ENDUSERPROFILENAME, certificateProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        assertEquals(CertificateProfile.SERVERPROFILENAME, certificateProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER));
        assertEquals(CertificateProfile.HARDTOKENSIGNPROFILENAME, certificateProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
        assertEquals(CertificateProfile.HARDTOKENAUTHENCPROFILENAME, certificateProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC));

        Map<Integer, String> map = certificateProfileSession.getCertificateProfileIdToNameMap();
        assertEquals(CertificateProfile.ENDUSERPROFILENAME, map.get(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS1");
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPMAPPINGS2");
    } 

    /**
     * Test of the cache of certificate profiles. This test depends on the default cache time of 1 second being used.
     * If you changed this config, certprofiles.cachetime, this test may fail. 
     */
    @Test
    public void test07CertificateProfileCache() throws Exception {
    	// First a check that we have the correct configuration, i.e. default
    	long cachetime = CesecoreConfiguration.getCacheCertificateProfileTime();
    	assertEquals(1000, cachetime);

    	// Add a profile
    	certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPCACHE1");
    	CertificateProfile ecp1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ecp1.setCNPostfix("foo");
        certificateProfileSession.addCertificateProfile(roleMgmgToken, "TESTCPCACHE1", ecp1);
    	
    	// Make sure profile has the right value from the beginning
        CertificateProfile ecp = certificateProfileSession.getCertificateProfile("TESTCPCACHE1");
        assertEquals("foo", ecp.getCNPostfix());
        ecp.setCNPostfix("bar");
        certificateProfileSession.changeCertificateProfile(roleMgmgToken, "TESTCPCACHE1", ecp);
    	// Read profile
        ecp = certificateProfileSession.getCertificateProfile("TESTCPCACHE1");
        assertEquals("bar", ecp.getCNPostfix());

        // Flush caches to reset cache timeout
        certificateProfileSession.flushProfileCache();
    	// Change profile, not flushing cache
        ecp.setCNPostfix("bar2000");
        certificateProfileSession.internalChangeCertificateProfileNoFlushCache(roleMgmgToken, "TESTCPCACHE1", ecp);
    	// read profile again, value should not be changed because it is cached
        ecp = certificateProfileSession.getCertificateProfile("TESTCPCACHE1");
        assertEquals("bar", ecp.getCNPostfix());
    	
    	// Wait 2 seconds and try again, now the cache should have been updated
    	Thread.sleep(2000);
        ecp = certificateProfileSession.getCertificateProfile("TESTCPCACHE1");
        assertEquals("bar2000", ecp.getCNPostfix());

        // Changing using the regular method however should immediately flush the cache
        ecp.setCNPostfix("barfoo");
        certificateProfileSession.changeCertificateProfile(roleMgmgToken, "TESTCPCACHE1", ecp);
        ecp = certificateProfileSession.getCertificateProfile("TESTCPCACHE1");
        assertEquals("barfoo", ecp.getCNPostfix());
        
        certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTCPCACHE1");

    } 

    @Test
    public void test08Authorization() throws Exception {
    	
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertProfileSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);

        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
            profile.setCRLDistributionPointURI("TEST");
            int id = certificateProfileSession.addCertificateProfile(roleMgmgToken, "TESTNOAUTH", profile);
            CertificateProfile cp = certificateProfileSession.getCertificateProfile(id);
            assertNotNull(cp);
            
            try {
                certificateProfileSession.addCertificateProfile(adminTokenNoAuth, "TESTNOAUTH1", profile);
            	assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            try {
                certificateProfileSession.cloneCertificateProfile(adminTokenNoAuth, "TESTNOAUTH", "TESTNOAUTH1", null);
            	assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            try {
                certificateProfileSession.renameCertificateProfile(adminTokenNoAuth, "TESTNOAUTH", "TESTNOAUTH1");
            	assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            try {
                certificateProfileSession.removeCertificateProfile(adminTokenNoAuth, "TESTNOAUTH");
            	assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            
    	} finally {
    		certificateProfileSession.removeCertificateProfile(roleMgmgToken, "TESTNOAUTH");
    	}
    }
    

    /** Test if we can detect that a certificate profile references to CA IDs and Publisher IDs. */
    @Test
    public void test09CertificateProfileReferenceDetection() throws Exception {
        log.trace(">test14CertificateProfileReferenceDetection()");
        final String NAME = "CertificateProfileReferenceDetection";
        final List<Integer> fakePublisherIds = new ArrayList<Integer>();
        fakePublisherIds.add(Integer.valueOf(1337));
        final List<Integer> fakeCaIds = new ArrayList<Integer>();
        fakeCaIds.add(Integer.valueOf(1338));
        
        try {
                try {
                        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
                        profile.setPublisherList(fakePublisherIds);
                        profile.setAvailableCAs(fakeCaIds);
                        certificateProfileSession.addCertificateProfile(roleMgmgToken, NAME, profile);
                } catch (CertificateProfileExistsException pee) {
                        log.warn("Failed to add Certificate Profile " + NAME + ". Assuming this is caused from a previous failed test..");
                }
                assertTrue("Unable to detect that Publisher Id was present in Certificate Profile.", certificateProfileSession.existsPublisherIdInCertificateProfiles(fakePublisherIds.get(0).intValue()));
                assertFalse("Unable to detect that Publisher Id was present in Certificate Profile.", certificateProfileSession.existsPublisherIdInCertificateProfiles(7331));
                assertTrue("Unable to detect that CA Id was present in Certificate Profile.", certificateProfileSession.existsCAIdInCertificateProfiles(fakeCaIds.get(0).intValue()));
                assertFalse("Unable to detect that CA Id was present in Certificate Profile.", certificateProfileSession.existsCAIdInCertificateProfiles(8331));
        } finally {
                certificateProfileSession.removeCertificateProfile(roleMgmgToken, NAME);
        }
        log.trace("<test14CertificateProfileReferenceDetection()");
    }

}
