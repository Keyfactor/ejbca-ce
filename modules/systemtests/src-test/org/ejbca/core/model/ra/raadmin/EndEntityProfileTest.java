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

package org.ejbca.core.model.ra.raadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the end entity profile entity bean.
 *
 * @version $Id$
 */
public class EndEntityProfileTest {
    private static final Logger log = Logger.getLogger(EndEntityProfileTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    
    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
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
            profile.addField(DnComponents.ORGANIZATIONUNIT);

            endEntityProfileSession.addEndEntityProfile(admin, "TEST", profile);

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
            endEntityProfileSession.renameEndEntityProfile(admin, "TEST", "TEST2");
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
            endEntityProfileSession.cloneEndEntityProfile(admin, "TEST2", "TEST");
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

        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(admin, "TEST");
        assertTrue("Retrieving EndEntityProfile failed", profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT) == 1);

        profile.addField(DnComponents.ORGANIZATIONUNIT);
        assertEquals(profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT), 2);

        // Change the profile, if save fails it should throw an exception
        endEntityProfileSession.changeEndEntityProfile(admin, "TEST", profile);

        log.trace("<test04EditEndEntityProfile()");
    }

    /**
     * removes all profiles
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test05removeEndEntityProfiles() throws Exception {
        log.trace(">test05removeEndEntityProfiles()");
        boolean ret = false;
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TEST");
            endEntityProfileSession.removeEndEntityProfile(admin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing End Entity Profile failed", ret);

        log.trace("<test05removeEndEntityProfiles()");
    }

    /**
     * Test if dynamic fields behave as expected
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test06testEndEntityProfilesDynamicFields() throws Exception {
        log.trace(">test06testEndEntityProfilesDynamicFields()");
        String testProfileName = "TESTDYNAMICFIELDS";
        String testString1 = "testString1";
        String testString2 = "testString2";
        boolean returnValue = true;
        // Create testprofile
        EndEntityProfile profile = new EndEntityProfile();
        endEntityProfileSession.addEndEntityProfile(admin, testProfileName, profile);
        // Add two dynamic fields
        profile = endEntityProfileSession.getEndEntityProfile(admin, testProfileName);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 0, testString1);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 1, testString2);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.DNSNAME);
        profile.setValue(DnComponents.DNSNAME, 0, testString1);
        profile.setValue(DnComponents.DNSNAME, 1, testString2);
        endEntityProfileSession.changeEndEntityProfile(admin, testProfileName, profile);
        // Remove first field
        profile = endEntityProfileSession.getEndEntityProfile(admin, testProfileName);
        profile.removeField(DnComponents.ORGANIZATIONUNIT, 0);
        profile.removeField(DnComponents.DNSNAME, 0);
        endEntityProfileSession.changeEndEntityProfile(admin, testProfileName, profile);
        // Test if changes are what we expected
        profile = endEntityProfileSession.getEndEntityProfile(admin, testProfileName);
        returnValue &= testString2.equals(profile.getValue(DnComponents.ORGANIZATIONUNIT, 0));
        returnValue &= testString2.equals(profile.getValue(DnComponents.DNSNAME, 0));
        assertTrue("Adding and removing dynamic fields to profile does not work properly.", returnValue);
        // Remove profile
        endEntityProfileSession.removeEndEntityProfile(admin, testProfileName);
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
            String password = profile.getAutoGeneratedPasswd();
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
        assertEquals(0, profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT));
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        assertEquals(1, profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT));

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
     * @throws UserDoesntFullfillEndEntityProfile 
     * @throws CertificateProfileExistsException 
     * @throws AuthorizationDeniedException 
     */
    @Test
    public void test10CardnumberRequired() throws CertificateProfileExistsException, AuthorizationDeniedException {
    	log.trace(">test10CardnumberRequired()");

        int caid = "CN=TEST EndEntityProfile,O=PrimeKey,C=SE".hashCode();
    	
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTCARDNUMBER");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(EndEntityProfile.CARDNUMBER);
        profile.setRequired(EndEntityProfile.CARDNUMBER, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(caid));

        String cardnumber = "foo123";
        boolean ret = false;
        try {
            endEntityProfileSession.addEndEntityProfile(admin, "TESTCARDNUMBER", profile);
        } catch (EndEntityProfileExistsException pee) {}    
            
        profile = endEntityProfileSession.getEndEntityProfile(admin, "TESTCARDNUMBER");
            
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=foo", caid, "", "", SecConst.USER_ENDUSER, endEntityProfileSession.getEndEntityProfileId(admin, "TESTCARDNUMBER"), SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        try {
			profile.doesUserFullfillEndEntityProfile(userdata, false);
		} catch (UserDoesntFullfillEndEntityProfile e) {
			log.debug(e.getMessage());
	        ret = true;
		}
		assertTrue("User fullfilled the End Entity Profile even though the cardnumber was not sett", ret);
            
		ret = false;
        userdata.setCardNumber(cardnumber);
        try {
			profile.doesUserFullfillEndEntityProfile(userdata, false);
			ret = true;
		} catch (UserDoesntFullfillEndEntityProfile e) {
			log.debug(e.getMessage());
			ret = false;
		}
        assertTrue("User did not full fill the End Entity Profile even though the card number was sett", ret);
        
        log.trace("<test10CardnumberRequired()");
    }

    /** Test if we can detect that a End Entity Profile references to CA IDs and Certificate Profile IDs. */
    @Test
   public void test11EndEntityProfileReferenceDetection() throws Exception {
        log.trace(">test11EndEntityProfileReferenceDetection()");
        final String NAME = "EndEntityProfileReferenceDetection";
        try {
        	try {
        		EndEntityProfile profile = new EndEntityProfile();
        		profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+1337);
        		profile.setValue(EndEntityProfile.AVAILCAS, 0, ""+1338);
        		endEntityProfileSession.addEndEntityProfile(admin, NAME, profile);
        	} catch (EndEntityProfileExistsException pee) {
        		log.warn("Failed to add Certificate Profile " + NAME + ". Assuming this is caused from a previous failed test..");
        	}
        	assertTrue("Unable to detect that Certificate Profile Id was present in End Entity Profile.", endEntityProfileSession.existsCertificateProfileInEndEntityProfiles(admin, 1337));
        	assertFalse("Unable to detect that Certificate Profile Id was not present in End Entity Profile.", endEntityProfileSession.existsCertificateProfileInEndEntityProfiles(admin, 7331));
        	assertTrue("Unable to detect that CA Id was present in Certificate Profile.", endEntityProfileSession.existsCAInEndEntityProfiles(admin, 1338));
        	assertFalse("Unable to detect that CA Id was not present in Certificate Profile.", endEntityProfileSession.existsCAInEndEntityProfiles(admin, 8331));
        } finally {
        	endEntityProfileSession.removeEndEntityProfile(admin, NAME);
        }
        log.trace("<test11EndEntityProfileReferenceDetection()");
    }

    /** Test if we can detect that a End Entity Profile references to CA IDs and Certificate Profile IDs. */
    @Test
   public void test12OperationsOnEmptyProfile() throws Exception {
        log.trace(">test12OperationsOnEmptyProfile()");
    	final EndEntityProfile profile = new EndEntityProfile();
        try {
        	endEntityProfileSession.addEndEntityProfile(admin, EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME, profile);
        	fail("Was able to add profile named " + EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME);
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	final int eepId = endEntityProfileSession.getEndEntityProfileId(admin, EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME);
        	endEntityProfileSession.addEndEntityProfile(admin, eepId, "somerandomname", profile);
        	fail("Was able to add profile with EEP Id " + eepId);
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.cloneEndEntityProfile(admin, "ignored", EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME);
        	fail("Clone to " + EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.renameEndEntityProfile(admin, "ignored", EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME);
        	fail("Rename to " + EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        try {
        	endEntityProfileSession.renameEndEntityProfile(admin, EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME, "ignored"	);
        	fail("Rename from " + EndEntityProfileSessionRemote.EMPTY_ENDENTITYPROFILENAME + " did not throw EndEntityProfileExistsException");
        } catch (EndEntityProfileExistsException pee) {
        	// Expected
        }
        log.trace("<test12OperationsOnEmptyProfile()");
    }
}
