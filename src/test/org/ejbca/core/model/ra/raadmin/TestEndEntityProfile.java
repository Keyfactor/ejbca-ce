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

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.dn.DnComponents;

/**
 * Tests the end entity profile entity bean.
 *
 * @version $Id: TestEndEntityProfile.java,v 1.2 2008-01-03 12:52:37 anatom Exp $
 */
public class TestEndEntityProfile extends TestCase {
    private static Logger log = Logger.getLogger(TestEndEntityProfile.class);
    private IRaAdminSessionRemote cacheAdmin;


    private static IRaAdminSessionHome cacheHome;

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

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IRaAdminSessionHome.JNDI_NAME);
                cacheHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);

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

            cacheAdmin.addEndEntityProfile(admin, "TEST", profile);

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
            cacheAdmin.renameEndEntityProfile(admin, "TEST", "TEST2");
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
            cacheAdmin.cloneEndEntityProfile(admin, "TEST2", "TEST");
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

        EndEntityProfile profile = cacheAdmin.getEndEntityProfile(admin, "TEST");
        assertTrue("Retrieving EndEntityProfile failed", profile.getNumberOfField(DnComponents.ORGANIZATIONUNIT) == 1);

        profile.addField(DnComponents.ORGANIZATIONUNIT);

        cacheAdmin.changeEndEntityProfile(admin, "TEST", profile);
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
            cacheAdmin.removeEndEntityProfile(admin, "TEST");
            cacheAdmin.removeEndEntityProfile(admin, "TEST2");
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
        cacheAdmin.addEndEntityProfile(admin, testProfileName, profile);
        // Add two dynamic fields
        profile = cacheAdmin.getEndEntityProfile(admin, testProfileName);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 0, testString1);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 1, testString2);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.DNSNAME);
        profile.setValue(DnComponents.DNSNAME, 0, testString1);
        profile.setValue(DnComponents.DNSNAME, 1, testString2);
        cacheAdmin.changeEndEntityProfile(admin, testProfileName, profile);
        // Remove first field
        profile = cacheAdmin.getEndEntityProfile(admin, testProfileName);
        profile.removeField(DnComponents.ORGANIZATIONUNIT, 0);
        profile.removeField(DnComponents.DNSNAME, 0);
        cacheAdmin.changeEndEntityProfile(admin, testProfileName, profile);
        // Test if changes are what we expected
        profile = cacheAdmin.getEndEntityProfile(admin, testProfileName);
        returnValue &= testString2.equals(profile.getValue(DnComponents.ORGANIZATIONUNIT, 0));
        returnValue &= testString2.equals(profile.getValue(DnComponents.DNSNAME, 0));
        // Remove profile
        cacheAdmin.removeEndEntityProfile(admin, testProfileName);
        assertTrue("Adding and removing dynamic fields to profile does not work properly.", returnValue);
        log.debug("<test06testEndEntityProfilesDynamicFields()");
    } // test06testEndEntityProfilesDynamicFields
}
