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

package org.ejbca.core.model.ra.raadmin;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the end entity profile entity bean.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EndEntityProfileSessionBeanTest extends RoleUsingTestCase {
    private static final Logger log = Logger.getLogger(EndEntityProfileSessionBeanTest.class);

    private static final String ROLENAME = "EndEntityProfileSessionTest";

    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);;
    
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken("EndEntityProfileSessionBeanTest");
    
    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole(null, ROLENAME, Arrays.asList(
                StandardRules.CAACCESSBASE.resource(),
                AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES,
                AccessRulesConstants.ENDENTITYPROFILEBASE
                ), null);
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    /**
     * adds a publishers to the database
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test01AddEndEntityProfile() throws Exception {
        log.trace(">test01AddEndEntityProfile()");
        boolean ret = false;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATIONALUNIT);

            endEntityProfileSession.addEndEntityProfile(roleMgmgToken, "TEST", profile);
            EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TEST");
            assertNotNull(eep);
            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }

        assertTrue("Creating End Entity Profile failed", ret);
        log.trace("<test01AddEndEntityProfile()");
    }

    /**
     * renames profile
     * 
     * @throws Exception
     *             error
     */
    @Test
   public void test02RenameEndEntityProfile() throws Exception {
        log.trace(">test02RenameEndEntityProfile()");

        boolean ret = false;
        try {
            endEntityProfileSession.renameEndEntityProfile(roleMgmgToken, "TEST", "TEST2");
            EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TEST");
            assertNull(eep);
            eep = endEntityProfileSession.getEndEntityProfile("TEST2");
            assertNotNull(eep);
            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }
        assertTrue("Renaming End Entity Profile failed", ret);

        log.trace("<test02RenameEndEntityProfile()");
    }

    /**
     * clones profile
     * 
     * @throws Exception
     *             error
     */
    @Test
   public void test03CloneEndEntityProfile() throws Exception {
        log.trace(">test03CloneEndEntityProfile()");

        boolean ret = false;
        try {
            endEntityProfileSession.cloneEndEntityProfile(roleMgmgToken, "TEST2", "TEST");
            EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TEST");
            assertNotNull(eep);
            eep = endEntityProfileSession.getEndEntityProfile("TEST2");
            assertNotNull(eep);
            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }
        assertTrue("Cloning End Entity Profile failed", ret);

        log.trace("<test03CloneEndEntityProfile()");
    }

    /**
     * edits profile
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test04EditEndEntityProfile() throws Exception {
        log.trace(">test04EditEndEntityProfile()");

        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile("TEST");
        assertTrue("Retrieving EndEntityProfile failed", profile.getNumberOfField(DnComponents.ORGANIZATIONALUNIT) == 1);

        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        assertEquals(profile.getNumberOfField(DnComponents.ORGANIZATIONALUNIT), 2);

        // Change the profile, if save fails it should throw an exception
        endEntityProfileSession.changeEndEntityProfile(roleMgmgToken, "TEST", profile);

        EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TEST");
        assertNotNull(eep);
        assertEquals(eep.getNumberOfField(DnComponents.ORGANIZATIONALUNIT), 2);

        log.trace("<test04EditEndEntityProfile()");
    }

    /**
     * removes all profiles
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test05RemoveEndEntityProfiles() throws Exception {
        log.trace(">test05removeEndEntityProfiles()");
        boolean ret = false;
        try {
            endEntityProfileSession.removeEndEntityProfile(roleMgmgToken, "TEST");
            endEntityProfileSession.removeEndEntityProfile(roleMgmgToken, "TEST2");
            EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TEST");
            assertNull(eep);
            eep = endEntityProfileSession.getEndEntityProfile("TEST2");
            assertNull(eep);
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing End Entity Profile failed", ret);

        log.trace("<test05removeEndEntityProfiles()");
    }

    private int createCertificateProfile(final AuthenticationToken admin, final String name, final int type) throws Exception {
        certificateProfileSession.removeCertificateProfile(admin, name);
        CertificateProfile profile = new CertificateProfile();
        profile.setType(type);
        certificateProfileSession.addCertificateProfile(admin, name, profile);
        int id = certificateProfileSession.getCertificateProfileId(name);
        assertTrue(id != 0);
        return id;
    }
    
    /**
     * Tests fetching all available certificate profiles associated with an end entity profile.
     * 
     * @throws Exception any exception.
     */
    @Test
    public void test05GetAvailableCertificateProfiles() throws Exception {
        final String cpProfileName1 = "test05CertificateProfile1";
        final String cpProfileName2 = "test05CertificateProfile2";
        final String eepProfileName = "test05EndEntityProfile";
        final EndEntityProfile eeProfile = new EndEntityProfile();
        try {
            endEntityProfileSession.addEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            final int eepId = endEntityProfileSession.getEndEntityProfileId(eepProfileName);
            // Test 0 available CPs for this EEP.
            final int cpId1 = createCertificateProfile(alwaysAllowToken, cpProfileName1, CertificateConstants.CERTTYPE_ENDENTITY);
            eeProfile.setAvailableCertificateProfileIds(Arrays.asList(new Integer[] { cpId1 }));
            endEntityProfileSession.changeEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            Map<String, Integer> map = endEntityProfileSession.getAvailableCertificateProfiles(alwaysAllowToken, eepId);
            assertEquals("getAvailableCertificateProfiles for an EEP with 1 CPs assigned should return 1.", map.size(), 1);
            
            // Test n>1 available CPs for this EEP.
            final int cpId2 = createCertificateProfile(alwaysAllowToken, cpProfileName2, CertificateConstants.CERTTYPE_ENDENTITY);
            eeProfile.setAvailableCertificateProfileIds(Arrays.asList(new Integer[] { cpId1, cpId2 }));
            endEntityProfileSession.changeEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            map = endEntityProfileSession.getAvailableCertificateProfiles(alwaysAllowToken, eepId);
            assertEquals("getAvailableCertificateProfiles for an EEP with 2 CPs assigned should return 2.", map.size(), 2);
        } finally {
            endEntityProfileSession.changeEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            endEntityProfileSession.removeEndEntityProfile(alwaysAllowToken, eepProfileName);
            certificateProfileSession.removeCertificateProfile(alwaysAllowToken, cpProfileName1);
            certificateProfileSession.removeCertificateProfile(alwaysAllowToken, cpProfileName2);
        }
    }
    
    /**
     * Tests fetching all available CAs associated with an end entity profile.
     * 
     * @throws Exception any exception.
     */
    @Test
    public void test05GetAvailableCAsInProfile() throws Exception {
        final String caName1 = "test05CA1";
        final String caName2 = "test05CA2";
        final String eepProfileName = "test05EndEntityProfile";
        final EndEntityProfile eeProfile = new EndEntityProfile();
        int cryptoTokenId1 = -1; 
        int cryptoTokenId2 = -1;
        CAToken catoken1 = null;
        CAToken catoken2 = null;
        X509CAInfo caInfo1 = null;
        X509CAInfo caInfo2 = null;
        try {
            endEntityProfileSession.addEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            final int eepId = endEntityProfileSession.getEndEntityProfileId(eepProfileName);
            
            // 1. Test results.
            // 1.1 Test no available CAs for this EEP.
            Map<String, Integer> map = endEntityProfileSession.getAvailableCasInProfile(alwaysAllowToken, eepId);
            assertTrue("getAvailableCAsInProfile for an EEP with no CAs assigned should return a map with size 0.", map.size() == 0);
            
            // 1.2 Test 1 available CAs for this EEP
            // Create first CA.
            cryptoTokenId1 = CryptoTokenTestUtils.createCryptoTokenForCA(alwaysAllowToken, "foo123".toCharArray(), caName1 + "_token", "1024");
            catoken1 = CaTestUtils.createCaToken(cryptoTokenId1, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            caInfo1 = getNewCAInfo(caName1, catoken1);
            caAdminSession.createCA(alwaysAllowToken, caInfo1);
            eeProfile.setAvailableCAs(Arrays.asList(new Integer[] { caInfo1.getCAId() }));
            endEntityProfileSession.changeEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            map = endEntityProfileSession.getAvailableCasInProfile(alwaysAllowToken, eepId);
            assertTrue("getAvailableCAsInProfile for an EEP with 1 CAs assigned should return a map with size 1.", map.size() == 1);
            assertTrue("CA name and ID must match.", map.get(caName1) == caInfo1.getCAId());
                        
            // 1.3 Test 2 available CAs for this EEP.
            // Create second CA.
            cryptoTokenId2 = CryptoTokenTestUtils.createCryptoTokenForCA(alwaysAllowToken, "foo123".toCharArray(), caName2 + "_token", "1024");
            catoken2 = CaTestUtils.createCaToken(cryptoTokenId2, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            caInfo2 = getNewCAInfo(caName2, catoken2);
            caAdminSession.createCA(alwaysAllowToken, caInfo2);
            eeProfile.setAvailableCAs(Arrays.asList(new Integer[] { caInfo1.getCAId(), caInfo2.getCAId() }));
            endEntityProfileSession.changeEndEntityProfile(alwaysAllowToken, eepProfileName, eeProfile);
            map = endEntityProfileSession.getAvailableCasInProfile(alwaysAllowToken, eepId);
            assertTrue("getAvailableCAsInProfile for an EEP with 2 CAs assigned should return a map with size 2.", map.size() == 2);
            assertTrue("CA name and ID must match.", map.get(caName1) == caInfo1.getCAId());
            assertTrue("CA name and ID must match.", map.get(caName2) == caInfo2.getCAId());
            
            // 2. Test exception handling.
            // 2.1 Test end entity profile not found.
            final int notExistingEepId = eepId + 1234;
            try {
                assertNull(endEntityProfileSession.getEndEntityProfile(notExistingEepId));
                endEntityProfileSession.getAvailableCasInProfile(alwaysAllowToken, notExistingEepId);
                fail("Request all CAs associated with an ent entity profile which does not exist must throw an exception.");
            } catch(Exception e) {
                assertTrue(
                        "Request all CAs associated with an ent entity profile which does not exist must throw an EndEntityProfileNotFoundException: "
                                + notExistingEepId,
                        e instanceof EndEntityProfileNotFoundException);
                assertEquals("End entity profile with ID " + notExistingEepId + " could not be found.", e.getMessage());
            }
            
        } finally {
            endEntityProfileSession.removeEndEntityProfile(alwaysAllowToken, eepProfileName);
            if (caInfo1 != null) {
                caSession.removeCA(alwaysAllowToken, caInfo1.getCAId());
            }
            if (caInfo2 != null) {
                caSession.removeCA(alwaysAllowToken, caInfo2.getCAId());
            }
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId1);
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId1);
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
        final X509CAInfo cainfo = new X509CAInfo("CN="+caname, caname, CAConstants.CA_ACTIVE, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("Used for testing CA import and export");
        cainfo.setExpireTime(new Date(System.currentTimeMillis()+364*24*3600*1000));
        cainfo.setDeltaCRLPeriod(0 * SimpleTime.MILLISECONDS_PER_HOUR);
        return cainfo;
    }
    
    /**
     * Test if dynamic fields behave as expected
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test06EndEntityProfilesDynamicFields() throws Exception {
        log.trace(">test06testEndEntityProfilesDynamicFields()");
        String testProfileName = "TESTDYNAMICFIELDS";
        String testString1 = "testString1";
        String testString2 = "testString2";
        boolean returnValue = true;
        // Create testprofile
        EndEntityProfile profile = new EndEntityProfile();
        endEntityProfileSession.addEndEntityProfile(roleMgmgToken, testProfileName, profile);
        // Add two dynamic fields
        profile = endEntityProfileSession.getEndEntityProfile(testProfileName);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.setValue(DnComponents.ORGANIZATIONALUNIT, 0, testString1);
        profile.setValue(DnComponents.ORGANIZATIONALUNIT, 1, testString2);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.DNSNAME);
        profile.setValue(DnComponents.DNSNAME, 0, testString1);
        profile.setValue(DnComponents.DNSNAME, 1, testString2);
        endEntityProfileSession.changeEndEntityProfile(roleMgmgToken, testProfileName, profile);
        // Remove first field
        profile = endEntityProfileSession.getEndEntityProfile(testProfileName);
        profile.removeField(DnComponents.ORGANIZATIONALUNIT, 0);
        profile.removeField(DnComponents.DNSNAME, 0);
        endEntityProfileSession.changeEndEntityProfile(roleMgmgToken, testProfileName, profile);
        // Test if changes are what we expected
        profile = endEntityProfileSession.getEndEntityProfile(testProfileName);
        returnValue &= testString2.equals(profile.getValue(DnComponents.ORGANIZATIONALUNIT, 0));
        returnValue &= testString2.equals(profile.getValue(DnComponents.DNSNAME, 0));
        assertTrue("Adding and removing dynamic fields to profile does not work properly.", returnValue);
        // Remove profile
        endEntityProfileSession.removeEndEntityProfile(roleMgmgToken, testProfileName);
        log.trace("<test06testEndEntityProfilesDynamicFields()");
    } // test06testEndEntityProfilesDynamicFields

    /**
     * Test if password autogeneration behaves as expected
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test07PasswordAutoGeneration() throws Exception {
        log.trace(">test07PasswordAutoGeneration()");
        // Create testprofile
        EndEntityProfile profile = new EndEntityProfile();
        profile.setValue(EndEntityProfile.AUTOGENPASSWORDTYPE, 0, PasswordGeneratorFactory.PASSWORDTYPE_DIGITS);
        profile.setValue(EndEntityProfile.AUTOGENPASSWORDLENGTH, 0, "13");
        final String DIGITS = "0123456789";
        for (int i = 0; i < 100; i++) {
            String password = profile.makeAutoGeneratedPassword();
            assertTrue("Autogenerated password is not of the requested length (was " + password.length() + ".", password.length() == 13);
            for (int j = 0; j < password.length(); j++) {
                assertTrue("Password was generated with a improper char '" + password.charAt(j) + "'.", DIGITS.contains("" + password.charAt(j)));
            }
        }
        log.trace("<test07PasswordAutoGeneration()");
    }

    /**
     * Test if field ids behave as expected
     * 
     * @throws Exception
     *             error
     */
    @Test
   public void test08FieldIds() throws Exception {
        log.trace(">test08FieldIds()");
        EndEntityProfile profile = new EndEntityProfile();

        // Simple one that is guaranteed to succeed.
        assertEquals(0, profile.getNumberOfField(DnComponents.ORGANIZATIONALUNIT));
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        assertEquals(1, profile.getNumberOfField(DnComponents.ORGANIZATIONALUNIT));

        // Newer one
        assertEquals(0, profile.getNumberOfField(DnComponents.TELEPHONENUMBER));
        profile.addField(DnComponents.TELEPHONENUMBER);
        assertEquals(1, profile.getNumberOfField(DnComponents.TELEPHONENUMBER));

        // One with high numbers
        assertEquals(1, profile.getNumberOfField(EndEntityProfile.STARTTIME));
        profile.addField(EndEntityProfile.STARTTIME);
        assertEquals(2, profile.getNumberOfField(EndEntityProfile.STARTTIME));
        log.trace("<test08FieldIds()");
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void test09Clone() throws Exception {
        EndEntityProfile profile = new EndEntityProfile();
        EndEntityProfile clone = (EndEntityProfile)profile.clone();
        HashMap profmap = (HashMap)profile.saveData();
        HashMap clonemap = (HashMap)clone.saveData();
        assertEquals(profmap.size(), clonemap.size());
        clonemap.put("FOO", "BAR");
        assertEquals(profmap.size()+1, clonemap.size());
        profmap.put("FOO", "BAR");
        assertEquals(profmap.size(), clonemap.size());
        profmap.put("FOO", "FAR");
        String profstr = (String)profmap.get("FOO");
        String clonestr = (String)clonemap.get("FOO");
        assertEquals("FAR", profstr);
        assertEquals("BAR", clonestr);
    }
    
    /**
     * Test if the cardnumber is required in an end entity profile, and if check it is set if it was required.
     * @throws CertificateProfileExistsException 
     * @throws AuthorizationDeniedException 
     * @throws EndEntityProfileNotFoundException 
     */
    @Test
    public void test10CardnumberRequired() throws CertificateProfileExistsException, AuthorizationDeniedException, EndEntityProfileNotFoundException {
 	log.trace(">test10CardnumberRequired()");

    	try {
    	    int caid = "CN=TEST EndEntityProfile,O=PrimeKey,C=SE".hashCode();

    	    EndEntityProfile profile = new EndEntityProfile();
    	    profile.addField(EndEntityProfile.CARDNUMBER);
    	    profile.setRequired(EndEntityProfile.CARDNUMBER, 0, true);
    	    profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
    	    String cardnumber = "foo123";
    	    boolean ret = false;
    	    try {
    	        endEntityProfileSession.addEndEntityProfile(roleMgmgToken, "TESTCARDNUMBER", profile);
    	    } catch (EndEntityProfileExistsException pee) {
    	        // NOPMD
    	    }    

    	    profile = endEntityProfileSession.getEndEntityProfile("TESTCARDNUMBER");

            EndEntityInformation userdata = new EndEntityInformation("foo", "CN=foo", caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                    endEntityProfileSession.getEndEntityProfileId("TESTCARDNUMBER"), CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_PEM, null);
            userdata.setPassword("foo123");
    	    try {
    	        profile.doesUserFulfillEndEntityProfile(userdata, false);
    	    } catch (EndEntityProfileValidationException e) {
    	        log.debug(e.getMessage());
    	        ret = true;
    	    }
    	    assertTrue("User fulfilled the End Entity Profile even though the cardnumber was not sett", ret);

    	    ret = false;
    	    userdata.setCardNumber(cardnumber);
    	    try {
    	        profile.doesUserFulfillEndEntityProfile(userdata, false);
    	        ret = true;
    	    } catch (EndEntityProfileValidationException e) {
    	        log.debug(e.getMessage());
    	        ret = false;
    	    }
    	    assertTrue("User did not full fill the End Entity Profile even though the card number was sett", ret);
    	} finally {
    	    endEntityProfileSession.removeEndEntityProfile(roleMgmgToken, "TESTCARDNUMBER");
    	}
    	log.trace("<test10CardnumberRequired()");
    }

    /** Test if we can detect that a End Entity Profile references to CA IDs and Certificate Profile IDs. */
    @Test
   public void test11EndEntityProfileReferenceDetection() throws Exception {
        log.trace(">test11EndEntityProfileReferenceDetection()");
        final String NAME = "EndEntityProfileReferenceDetection";
        try {
            // Get a CA that really does exist, otherwise we will not be "authorized" to this CA
            final Collection<Integer> caIds = caSession.getAllCaIds();
            final int caid = caIds.iterator().next();
        	try {
        		EndEntityProfile profile = new EndEntityProfile();
        		profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+1337);
        		profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(caid));
        		endEntityProfileSession.addEndEntityProfile(roleMgmgToken, NAME, profile);
        	} catch (EndEntityProfileExistsException pee) {
        		log.warn("Failed to add Certificate Profile " + NAME + ". Assuming this is caused from a previous failed test..");
        	}
        	assertFalse("Unable to detect that Certificate Profile Id was present in End Entity Profile.", endEntityProfileSession.getEndEntityProfilesUsingCertificateProfile(1337).isEmpty());
        	assertTrue("Unable to detect that Certificate Profile Id was not present in End Entity Profile.", endEntityProfileSession.getEndEntityProfilesUsingCertificateProfile(7331).isEmpty());
        	assertTrue("Unable to detect that CA Id was present in Certificate Profile.", endEntityProfileSession.existsCAInEndEntityProfiles(caid));
        	assertFalse("Unable to detect that CA Id was not present in Certificate Profile.", endEntityProfileSession.existsCAInEndEntityProfiles(8331));
        } finally {
        	endEntityProfileSession.removeEndEntityProfile(roleMgmgToken, NAME);
        }
        log.trace("<test11EndEntityProfileReferenceDetection()");
    }

    /** Test if we can detect that a End Entity Profile references to CA IDs and Certificate Profile IDs. */
    @Test
   public void test12OperationsOnEmptyProfile() throws Exception {
        log.trace(">test12OperationsOnEmptyProfile()");
    	final EndEntityProfile profile = new EndEntityProfile();
        try {
        	endEntityProfileSession.addEndEntityProfile(roleMgmgToken, EndEntityConstants.EMPTY_ENDENTITYPROFILENAME, profile);
        	fail("Was able to add profile named " + EndEntityConstants.EMPTY_ENDENTITYPROFILENAME);
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	final int eepId = endEntityProfileSession.getEndEntityProfileId(EndEntityConstants.EMPTY_ENDENTITYPROFILENAME);
        	endEntityProfileSession.addEndEntityProfile(roleMgmgToken, eepId, "somerandomname", profile);
        	fail("Was able to add profile with EEP Id " + eepId);
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.cloneEndEntityProfile(roleMgmgToken, "ignored", EndEntityConstants.EMPTY_ENDENTITYPROFILENAME);
        	fail("Clone to " + EndEntityConstants.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.renameEndEntityProfile(roleMgmgToken, "ignored", EndEntityConstants.EMPTY_ENDENTITYPROFILENAME);
        	fail("Rename to " + EndEntityConstants.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.renameEndEntityProfile(roleMgmgToken, EndEntityConstants.EMPTY_ENDENTITYPROFILENAME, "ignored"	);
        	fail("Rename from " + EndEntityConstants.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        log.trace("<test12OperationsOnEmptyProfile()");
    }
    
    @Test
    public void testAuthorization() throws Exception {
        log.trace(">testAuthorization");
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test EndEntityProfileSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);
        try {
            EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile("TESTEEPROFNOAUTH");
            assertNull(eep);
            EndEntityProfile profile = new EndEntityProfile();
            profile.setAvailableCAs(Collections.singletonList(123));
            endEntityProfileSession.addEndEntityProfile(roleMgmgToken, "TESTEEPROFNOAUTH", profile);
            eep = endEntityProfileSession.getEndEntityProfile("TESTEEPROFNOAUTH");
            assertNotNull(eep);
            
            try {
                endEntityProfileSession.addEndEntityProfile(adminTokenNoAuth, "TESTEEPROFNOAUTH1", profile);
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            try {
                endEntityProfileSession.changeEndEntityProfile(adminTokenNoAuth, "TESTEEPROFNOAUTH", profile);
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            try {
                endEntityProfileSession.cloneEndEntityProfile(adminTokenNoAuth, "TESTEEPROFNOAUTH", "TESTEEPROFNOAUTH1");
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            try {
                endEntityProfileSession.renameEndEntityProfile(adminTokenNoAuth, "TESTEEPROFNOAUTH", "TESTEEPROFNOAUTH1");
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            try {
                endEntityProfileSession.removeEndEntityProfile(adminTokenNoAuth, "TESTEEPROFNOAUTH");
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            // Test getting authorized end entity profiles IDs, get only profiles we have create access to
            // First check that root access can retrieve all EEPs (even with a non-existing CA)
            Collection<Integer> ids1 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(alwaysAllowToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertNotNull(ids1);
            // Some IDs we know should be in there (there might be others as well depending on the system the test runs on so we can't be too strict
            final int id1 = endEntityProfileSession.getEndEntityProfileId("TESTEEPROFNOAUTH");
            // We cannot access an EEP with a non-existing CA unless we are root
            Collection<Integer> ids3 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(roleMgmgToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertNotNull(ids3);
            assertFalse("Id should not be amongst authorized Ids: "+id1, ids3.contains(id1));
            // Should not be in this one, since not authorized
            Collection<Integer> ids2 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(adminTokenNoAuth, AccessRulesConstants.CREATE_END_ENTITY);
            assertNotNull(ids2);
            assertFalse("Id should not be amongst authorized Ids: "+id1, ids2.contains(id1));

            // EE profiles checks for authorization to the CAs that are present as AVAILCAs.
            // So we have to deny the admin specifically for a certain CA
            Collection<Integer> caids = caSession.getAllCaIds();
            int caid = caids.iterator().next();
            profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(1337));
            profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(caid));
            // It should work now
            endEntityProfileSession.changeEndEntityProfile(roleMgmgToken, "TESTEEPROFNOAUTH", profile);
            // Add a deny rule to the role
            final Role roleInstance1 = roleSession.getRole(alwaysAllowToken, null, ROLENAME);
            roleInstance1.getAccessRules().put(StandardRules.CAACCESS.resource() + caid, Role.STATE_DENY);
            roleSession.persistRole(alwaysAllowToken, roleInstance1);
            try {
                // Now it should fail
                endEntityProfileSession.changeEndEntityProfile(roleMgmgToken, "TESTEEPROFNOAUTH", profile);
                assertTrue("should throw", false);
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            // It should not be among authorized EE profiles wither, since we don't have access to the CA
            ids1 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(roleMgmgToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertFalse("Id should not be amongst authorized Ids: "+id1, ids1.contains(id1));
            // Remove the deny rule again so we can remove the profile later on
            final Role roleInstance2 = roleSession.getRole(alwaysAllowToken, null, ROLENAME);
            roleInstance2.getAccessRules().remove(AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caid));
            roleSession.persistRole(alwaysAllowToken, roleInstance2);
            // SHould be back
            ids1 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(roleMgmgToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertTrue("Id should be amongst authorized Ids: "+id1, ids1.contains(id1));
            // Also test the rule CREATE_END_ENTITY
            // First remove access to this EE profile by setting /endentityprofilesrules/id1/create_end_entity to decline
            final Role roleInstance3 = roleSession.getRole(alwaysAllowToken, null, ROLENAME);
            roleInstance3.getAccessRules().put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + id1 + AccessRulesConstants.CREATE_END_ENTITY, Role.STATE_DENY);
            roleSession.persistRole(alwaysAllowToken, roleInstance3);
            ids1 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(roleMgmgToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertFalse("Id should not be amongst authorized Ids: "+id1, ids1.contains(id1));
            // Replace the deny rule with an accept rule so we can edit the profile later on
            final Role roleInstance4 = roleSession.getRole(alwaysAllowToken, null, ROLENAME);
            roleInstance4.getAccessRules().put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + id1 + AccessRulesConstants.CREATE_END_ENTITY, Role.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowToken, roleInstance4);
            ids1 = endEntityProfileSession.getAuthorizedEndEntityProfileIds(roleMgmgToken, AccessRulesConstants.CREATE_END_ENTITY);
            assertTrue("Id should be amongst authorized Ids: "+id1, ids1.contains(id1));
        } finally {
            for (final String eepName : Arrays.asList("TESTEEPROFNOAUTH", "TESTEEPROFNOAUTH1", "TESTEEPROFNOAUTH2")) {
                try {
                    endEntityProfileSession.removeEndEntityProfile(alwaysAllowToken, eepName);
                } catch (Exception e) {
                    log.debug(e.getMessage());
                }
            }
            log.trace("<testAuthorization");
        }
    }
}
