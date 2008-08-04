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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.TestTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Tests the end entity profile entity bean.
 *
 * @version $Id$
 */
public class TestEndEntityProfile extends TestCase {
    private static final Logger log = Logger.getLogger(TestEndEntityProfile.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestEndEntityProfile object.
     *
     * @param name name
     */
    public TestEndEntityProfile(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    /**
     * adds a publishers to the database
     *
     * @throws Exception error
     */
    public void test01AddEndEntityProfile() throws Exception {
        log.debug(">test01AddEndEntityProfile()");
        boolean ret = false;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATIONUNIT);

            TestTools.getRaAdminSession().addEndEntityProfile(admin, "TEST", profile);

            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }

        assertTrue("Creating End Entity Profile failed", ret);
        log.debug("<test01AddEndEntityProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameEndEntityProfile() throws Exception {
        log.debug(">test02RenameEndEntityProfile()");

        boolean ret = false;
        try {
            TestTools.getRaAdminSession().renameEndEntityProfile(admin, "TEST", "TEST2");
            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }
        assertTrue("Renaming End Entity Profile failed", ret);

        log.debug("<test02RenameEndEntityProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneEndEntityProfile() throws Exception {
        log.debug(">test03CloneEndEntityProfile()");

        boolean ret = false;
        try {
            TestTools.getRaAdminSession().cloneEndEntityProfile(admin, "TEST2", "TEST");
            ret = true;
        } catch (EndEntityProfileExistsException pee) {
        }
        assertTrue("Cloning End Entity Profile failed", ret);

        log.debug("<test03CloneEndEntityProfile()");
    }


    /**
     * edits profile
     *
     * @throws Exception error
     */
    public void test04EditEndEntityProfile() throws Exception {
        log.debug(">test04EditEndEntityProfile()");

        boolean ret = false;

        EndEntityProfile profile = TestTools.getRaAdminSession().getEndEntityProfile(admin, "TEST");
        assertTrue("Retrieving EndEntityProfile failed", profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT) == 1);

        profile.addField(DnComponents.ORGANIZATIONUNIT);

        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TEST", profile);
        ret = true;

        assertTrue("Editing EndEntityProfile failed", ret);


        log.debug("<test04EditEndEntityProfile()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeEndEntityProfiles() throws Exception {
        log.debug(">test05removeEndEntityProfiles()");
        boolean ret = false;
        try {
            TestTools.getRaAdminSession().removeEndEntityProfile(admin, "TEST");
            TestTools.getRaAdminSession().removeEndEntityProfile(admin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing End Entity Profile failed", ret);

        log.debug("<test05removeEndEntityProfiles()");
    }

    /**
     * Test if dynamic fields behave as expected
     * @throws Exception error
     */
    public void test06testEndEntityProfilesDynamicFields() throws Exception {
        log.debug(">test06testEndEntityProfilesDynamicFields()");
        String testProfileName = "TESTDYNAMICFIELDS";
        String testString1 = "testString1";
        String testString2 = "testString2";
        boolean returnValue = true;
    	// Create testprofile
        EndEntityProfile profile = new EndEntityProfile();
        TestTools.getRaAdminSession().addEndEntityProfile(admin, testProfileName, profile);
        // Add two dynamic fields
        profile = TestTools.getRaAdminSession().getEndEntityProfile(admin, testProfileName);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 0, testString1);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 1, testString2);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.DNSNAME);
        profile.setValue(DnComponents.DNSNAME, 0, testString1);
        profile.setValue(DnComponents.DNSNAME, 1, testString2);
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, testProfileName, profile);
        // Remove first field
        profile = TestTools.getRaAdminSession().getEndEntityProfile(admin, testProfileName);
        profile.removeField(DnComponents.ORGANIZATIONUNIT, 0);
        profile.removeField(DnComponents.DNSNAME, 0);
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, testProfileName, profile);
        // Test if changes are what we expected
        profile = TestTools.getRaAdminSession().getEndEntityProfile(admin, testProfileName);
        returnValue &= testString2.equals(profile.getValue(DnComponents.ORGANIZATIONUNIT, 0));
        returnValue &= testString2.equals(profile.getValue(DnComponents.DNSNAME, 0));
        // Remove profile
        TestTools.getRaAdminSession().removeEndEntityProfile(admin, testProfileName);
        assertTrue("Adding and removing dynamic fields to profile does not work properly.", returnValue);
        log.debug("<test06testEndEntityProfilesDynamicFields()");
    } // test06testEndEntityProfilesDynamicFields

    /**
     * Test if password autogeneration behaves as expected
     * @throws Exception error
     */
    public void test07PasswordAutoGeneration() throws Exception {
        log.debug(">test07PasswordAutoGeneration()");
    	// Create testprofile
        EndEntityProfile profile = new EndEntityProfile();
        profile.setValue(EndEntityProfile.AUTOGENPASSWORDTYPE, 0, PasswordGeneratorFactory.PASSWORDTYPE_DIGITS);
        profile.setValue(EndEntityProfile.AUTOGENPASSWORDLENGTH, 0, "13");
        final String DIGITS = "0123456789";
        for (int i=0; i<100; i++) {
            String password = profile.getAutoGeneratedPasswd();
            assertTrue("Autogenerated password is not of the requested length (was "+ password.length() +".", password.length() == 13);
            for (int j=0; j<password.length(); j++) {
            	assertTrue("Password was generated with a improper char '" + password.charAt(j) + "'.", DIGITS.contains("" + password.charAt(j)));
            }
        }
        log.debug("<test07PasswordAutoGeneration()");
    }
}
