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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the EndEntityInformation entity bean and some parts of EndEntityManagementSession.
 * 
 * @version $Id$
 */
public class EndEntityManagementTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(EndEntityManagementTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserDataTest"));

    private static final String PROFILE_CACHE_NAME_1 = "TESTEEPROFCACHE1";
    private static final String PROFILE_CACHE_NAME_2 = "TESTEEPROFCACHE2";
    
    private int caid = getTestCAId();

    private static String username;

    private static String pwd;

    /** variable used to hold a flag value so we can reset it after we have done the tests */
    private static boolean gcEELimitations;

    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityManagementProxySessionRemote endEntityManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Global configuration must have "Enable End Entity Profile Limitations" set to true in order for
        // the request counter tests to pass, we check if we are allowed to set this value or not
        // The value is reset to whatever it was from the beginning in the last "clean up" test.
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        gcEELimitations = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(true);
        globalConfigurationSession.saveConfiguration(admin, gc);
        createNewUser();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

        // Reset the value of "EnableEndEntityProfileLimitations" to whatever it was before we ran test00SetEnableEndEntityProfileLimitations
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        gc.setEnableEndEntityProfileLimitations(gcEELimitations);
        globalConfigurationSession.saveConfiguration(admin, gc);

        // Delete test users we created

        endEntityManagementSession.deleteUser(admin, username);

        endEntityProfileSession.removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");

        endEntityProfileSession.removeEndEntityProfile(admin, PROFILE_CACHE_NAME_1);

        endEntityProfileSession.removeEndEntityProfile(admin, PROFILE_CACHE_NAME_2);

    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    public void createNewUser() throws Exception {
        username = genRandomUserName();
        pwd = genRandomPwd();
        endEntityManagementSession.addUser(admin, username, pwd, "C=SE,O=AnaTom,CN=" + username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
    }

    @Test
    public void testLookupAndChangeUser() throws Exception {
        log.trace(">test02LookupAndChangeUser()");

        log.debug("username=" + username);
        EndEntityInformation data2 = endEntityAccessSession.findUser(admin, username);
        log.debug("found by key! =" + data2);
        log.debug("username=" + data2.getUsername());
        assertTrue("wrong username", data2.getUsername().equals(username));
        log.debug("subject=" + data2.getDN());
        assertTrue("wrong DN", data2.getDN().indexOf(username) != -1);
        log.debug("email=" + data2.getEmail());
        assertNull("wrong email", data2.getEmail());
        log.debug("status=" + data2.getStatus());
        assertTrue("wrong status", data2.getStatus() == EndEntityConstants.STATUS_NEW);
        log.debug("type=" + data2.getType());
        assertTrue("wrong type", data2.getType().isType(EndEntityTypes.INVALID));
        assertTrue("wrong pwd (foo123 works)", endEntityManagementSession.verifyPassword(admin, username, "foo123") == false);
        assertTrue("wrong pwd " + pwd, endEntityManagementSession.verifyPassword(admin, username, pwd));

        // Change DN
        EndEntityInformation endEntity = new EndEntityInformation(username,  "C=SE,O=AnaTom,OU=Engineering,CN=" + username,
                caid, null, 
                username + "@anatom.se", EndEntityConstants.STATUS_GENERATED, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.EMPTY_ENDENTITYPROFILE,  CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, 0,
                null);
        endEntity.setPassword("foo123");
        endEntityManagementSession.changeUser(admin, endEntity, false);  
        log.debug("Changed it");
        log.trace("<test02LookupAndChangeUser()");

        EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
        log.debug("found by key! =" + data);
        log.debug("username=" + data.getUsername());
        assertTrue("wrong username", data.getUsername().equals(username));
        log.debug("subject=" + data.getDN());
        assertTrue("wrong DN (cn)", data.getDN().indexOf(username) != -1);
        assertTrue("wrong DN (ou)", data.getDN().indexOf("Engineering") != -1);
        log.debug("email=" + data.getEmail());
        assertNotNull("Email should not be null now.", data.getEmail());
        assertTrue("wrong email", data.getEmail().equals(username + "@anatom.se"));
        log.debug("status=" + data.getStatus());
        assertTrue("wrong status", data.getStatus() == EndEntityConstants.STATUS_GENERATED);
        log.debug("type=" + data.getType());
        assertTrue("wrong type", data.getType().isType(EndEntityTypes.ENDUSER));
        assertTrue("wrong pwd foo123", endEntityManagementSession.verifyPassword(admin, username, "foo123"));
        assertTrue("wrong pwd (" + pwd + " works)" + pwd, endEntityManagementSession.verifyPassword(admin, username, pwd) == false);

        // Use clear text pwd instead, new email, reverse DN again
        EndEntityInformation user = new EndEntityInformation(username,  "C=SE,O=AnaTom,CN=" + username,
                caid, null, 
                username + "@anatom.nu", EndEntityConstants.STATUS_GENERATED, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.EMPTY_ENDENTITYPROFILE,  CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, 0,
                null);
        user.setPassword("foo234");
        endEntityManagementSession.changeUser(admin, user, true);  
        log.trace("<test03LookupChangedUser()");

        data = endEntityAccessSession.findUser(admin, username);
        log.debug("found by key! =" + data);
        log.debug("username=" + data.getUsername());
        assertTrue("wrong username", data.getUsername().equals(username));
        log.debug("subject=" + data.getDN());
        assertTrue("wrong DN", data.getDN().indexOf(username) != -1);
        assertTrue("wrong DN", data.getDN().indexOf("Engineering") == -1);
        log.debug("email=" + data.getEmail());
        assertNotNull("Email should not be null now.", data.getEmail());
        assertTrue("wrong email", data.getEmail().equals(username + "@anatom.nu"));
        log.debug("status=" + data.getStatus());
        assertTrue("wrong status", data.getStatus() == EndEntityConstants.STATUS_GENERATED);
        log.debug("type=" + data.getType());
        assertTrue("wrong type", data.getType().isType(EndEntityTypes.ENDUSER));
        assertTrue("wrong pwd foo234", endEntityManagementSession.verifyPassword(admin, username, "foo234"));
        assertEquals("wrong clear pwd foo234", data.getPassword(), "foo234");
        assertTrue("wrong pwd (" + pwd + " works)", endEntityManagementSession.verifyPassword(admin, username, pwd) == false);

        endEntityManagementSession.setPassword(admin, username, "foo234");
        log.trace("<test03LookupChangedUser2()");
    }
    
    @Test
    public void testListNewUser() throws Exception {
        log.trace(">test05ListNewUser()");

        Collection<EndEntityInformation> coll = endEntityManagementSession.findAllUsersByStatus(admin, EndEntityConstants.STATUS_NEW);
        Iterator<EndEntityInformation> iter = coll.iterator();
        while (iter.hasNext()) {

            EndEntityInformation data = iter.next();
            log.debug("New user: " + data.getUsername() + ", " + data.getDN() + ", " + data.getEmail() + ", " + data.getStatus() + ", "
                    + data.getType());
            endEntityManagementSession.setUserStatus(admin, data.getUsername(), EndEntityConstants.STATUS_GENERATED);
        }

        Collection<EndEntityInformation> coll1 = endEntityManagementSession.findAllUsersByStatus(admin, EndEntityConstants.STATUS_NEW);
        assertTrue("found NEW users though there should be none!", coll1.isEmpty());
        log.trace("<test05ListNewUser()");
    }

    @Test
    public void testRequestCounter() throws Exception {
        log.trace(">test06RequestCounter()");

        // Change already existing user to add extended information with counter
        EndEntityInformation user = new EndEntityInformation(username, "C=SE,O=AnaTom,CN=" + username, caid, null, null, EndEntityTypes.INVALID.toEndEntityType(),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setStatus(EndEntityConstants.STATUS_GENERATED);
        endEntityManagementSession.changeUser(admin, user, false);

        // Default value should be 1, so it should return 0
        int counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);
        // Default value should be 1, so it should return 0
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);

        // Now add extended information with allowed requests 2
        ExtendedInformation ei = new ExtendedInformation();
        int allowedrequests = 2;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user = new EndEntityInformation(username, "C=SE,O=AnaTom,CN=" + username, caid, null, null, EndEntityTypes.INVALID.toEndEntityType(),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ei);
        boolean thrown = false;
        try {
            endEntityManagementSession.changeUser(admin, user, false);
        } catch (EndEntityProfileValidationException e) {
            thrown = true;
        }
        // This requires "Enable end entity profile limitations" to be checked in admin GUI->System configuration
        assertTrue(thrown);
        // decrease the value, since we use the empty end entity profile, the counter will not be used
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);

        // Test that it works correctly with end entity profiles using the counter
        int pid = 0;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.addField(DnComponents.COMMONNAME);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);
            profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
            endEntityProfileSession.addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
            pid = endEntityProfileSession.getEndEntityProfileId("TESTREQUESTCOUNTER");
        } catch (EndEntityProfileExistsException pee) {
            assertTrue("Can not create end entity profile", false);
        }
        // Now add extended information with allowed requests 2
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user = new EndEntityInformation(username, "C=SE,O=AnaTom,CN=" + username, caid, null, null, EndEntityTypes.INVALID.toEndEntityType(), pid,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ei);
        thrown = false;
        try {
            endEntityManagementSession.changeUser(admin, user, false);
        } catch (EndEntityProfileValidationException e) {
            thrown = true;
        }
        assertTrue(thrown);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);
        // decrease the value again, default value when the counter is not used is 0
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);

        // Now allow the counter
        EndEntityProfile ep = endEntityProfileSession.getEndEntityProfile(pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "2");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        // This time changeUser will be ok
        endEntityManagementSession.changeUser(admin, user, false);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(1, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(-1, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(-1, counter);

        // Now disallow the counter, it will be deleted from the user
        ep = endEntityProfileSession.getEndEntityProfile(pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedInformation();
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, null);
        user.setExtendedInformation(ei);
        endEntityManagementSession.changeUser(admin, user, false);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);

        // allow the counter
        ep = endEntityProfileSession.getEndEntityProfile(pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "2");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedInformation();
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, "0");
        user.setExtendedInformation(ei);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user, false);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(1, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(-1, counter);

        // test setuserstatus it will re-set the counter
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_GENERATED);
        ep = endEntityProfileSession.getEndEntityProfile(pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "3");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_NEW);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(2, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(1, counter);
        // test setuserstatus again it will not re-set the counter if it is already new
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_NEW);
        assertEquals(1, counter);
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(0, counter); // sets status to generated
        // decrease the value again
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(-1, counter);

        // test setuserstatus again it will re-set the counter since status is generated
        ep = endEntityProfileSession.getEndEntityProfile(pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "3");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_NEW);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(2, counter);

        // Also changeUser to new from something else will re-set status, if ei value is 0
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, "0");
        user.setExtendedInformation(ei);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user, false);
        // decrease the value
        counter = endEntityManagementProxySession.decRequestCounter(username);
        assertEquals(2, counter);

        // Test set and re-set logic

        // The profile has 3 as default value, if I change user with status to generated and value 2 it should be set as that
        EndEntityInformation user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedInformation(ei);
        user1.setStatus(EndEntityConstants.STATUS_GENERATED);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        String value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("2", value);
        // If I change user with status to new and value 1 it should be set as that
        ei = new ExtendedInformation();
        allowedrequests = 1;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedInformation(ei);
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I set status to new again, with noting changed, nothing should change
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_NEW);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // The same when I change the user
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to generated, nothing should happen
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_GENERATED);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to new from generated the default value should be used
        endEntityManagementSession.setUserStatus(admin, user.getUsername(), EndEntityConstants.STATUS_NEW);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // It should be possible to simply set the value to 0
        ei = new ExtendedInformation();
        allowedrequests = 0;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedInformation(ei);
        user1.setStatus(EndEntityConstants.STATUS_GENERATED);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Changing again to new, with 0 passed in will set the default value
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // Set back to 0
        user1.setStatus(EndEntityConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, "0");
        user1.setExtendedInformation(ei);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        value = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Setting with null value will always remove the request counter (the whole extendedinformatin actually)
        user1.setExtendedInformation(null);
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, user1, false);
        user1 = endEntityAccessSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedInformation();
        assertNull(ei);

        log.trace("<test06RequestCounter()");
    }

    @Test
    public void testEndEntityProfileMappings() throws Exception {
        // Add a couple of profiles and verify that the mappings and get functions work
        EndEntityProfile profile1 = new EndEntityProfile();
        profile1.setPrinterName("foo");
        endEntityProfileSession.addEndEntityProfile(admin, PROFILE_CACHE_NAME_1, profile1);
        EndEntityProfile profile2 = new EndEntityProfile();
        profile2.setPrinterName("bar");
        endEntityProfileSession.addEndEntityProfile(admin, PROFILE_CACHE_NAME_2, profile2);
        int pid = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_1);
        String name = endEntityProfileSession.getEndEntityProfileName(pid);
        int pid1 = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_1);
        String name1 = endEntityProfileSession.getEndEntityProfileName(pid1);
        assertEquals(pid, pid1);
        assertEquals(name, name1);
        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(pid);
        assertEquals("foo", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(name);
        assertEquals("foo", profile.getPrinterName());

        int pid2 = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_2);
        String name2 = endEntityProfileSession.getEndEntityProfileName(pid2);
        profile = endEntityProfileSession.getEndEntityProfile(pid2);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(name2);
        assertEquals("bar", profile.getPrinterName());

        // flush caches and make sure it is read correctly again
        endEntityProfileSession.flushProfileCache();

        int pid3 = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_1);
        String name3 = endEntityProfileSession.getEndEntityProfileName(pid3);
        assertEquals(pid1, pid3);
        assertEquals(name1, name3);
        profile = endEntityProfileSession.getEndEntityProfile(pid3);
        assertEquals("foo", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(name3);
        assertEquals("foo", profile.getPrinterName());

        int pid4 = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_2);
        String name4 = endEntityProfileSession.getEndEntityProfileName(pid4);
        assertEquals(pid2, pid4);
        assertEquals(name2, name4);
        profile = endEntityProfileSession.getEndEntityProfile(pid4);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(name4);
        assertEquals("bar", profile.getPrinterName());

        // Remove a profile and make sure it is not cached still
        endEntityProfileSession.removeEndEntityProfile(admin, PROFILE_CACHE_NAME_1);
        profile = endEntityProfileSession.getEndEntityProfile(pid1);
        assertNull(profile);
        try {
         endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_1);
         fail();
        } catch(EndEntityProfileNotFoundException e) {
            //We should end up here.
        }

        // But the other, non-removed profile should still be there
        int pid6 = endEntityProfileSession.getEndEntityProfileId(PROFILE_CACHE_NAME_2);
        String name6 = endEntityProfileSession.getEndEntityProfileName(pid6);
        assertEquals(pid2, pid6);
        assertEquals(name2, name6);
        profile = endEntityProfileSession.getEndEntityProfile(pid6);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(name6);
        assertEquals("bar", profile.getPrinterName());
    } // test07EndEntityProfileMappings

    /**
     * Test of the cache of end entity profiles. This test depends on the default cache time of 1 second being used. If you changed this config,
     * eeprofiles.cachetime, this test may fail.
     */
    @Test
    public void testEndEntityProfileCache() throws Exception {
        EndEntityProfile profile2 = new EndEntityProfile();
        profile2.setPrinterName("bar");
        endEntityProfileSession.addEndEntityProfile(admin, PROFILE_CACHE_NAME_2, profile2);
        
        // First a check that we have the correct configuration, i.e. default
        long cachetime = EjbcaConfiguration.getCacheEndEntityProfileTime();
        assertEquals(1000, cachetime);
        // Make sure profile has the right value from the beginning
        EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(PROFILE_CACHE_NAME_2);
        eep.setAllowMergeDnWebServices(false);
        endEntityProfileSession.changeEndEntityProfile(admin, PROFILE_CACHE_NAME_2, eep);
        // Read profile
        eep = endEntityProfileSession.getEndEntityProfile(PROFILE_CACHE_NAME_2);
        boolean value = eep.getAllowMergeDnWebServices();
        assertFalse(value);

        // Flush caches to reset cache timeout
        endEntityProfileSession.flushProfileCache();
        // Change profile, not flushing cache
        eep.setAllowMergeDnWebServices(true);
        endEntityProfileSession.internalChangeEndEntityProfileNoFlushCache(admin, PROFILE_CACHE_NAME_2, eep);

        // Wait 2 seconds and try again, now the cache should have been updated
        Thread.sleep(2000);
        eep = endEntityProfileSession.getEndEntityProfile(PROFILE_CACHE_NAME_2);
        value = eep.getAllowMergeDnWebServices();
        assertTrue(value);

        // Changing using the regular method however should immediately flush the cache
        eep.setAllowMergeDnWebServices(false);
        endEntityProfileSession.changeEndEntityProfile(admin, PROFILE_CACHE_NAME_2, eep);
        eep = endEntityProfileSession.getEndEntityProfile(PROFILE_CACHE_NAME_2);
        value = eep.getAllowMergeDnWebServices();
        assertFalse(value);
    }

    /**
     * Verify that there can be two different users with the same name, but in different case.
     */
    @Test
    public void testVerifyUserNameCaseSensitivity() throws Exception {
        String rnd = "sens" + genRandomUserName();
        String username1 = rnd.toLowerCase();
        String username2 = rnd.toUpperCase();
        final String pwd = genRandomPwd();
        endEntityManagementSession.addUser(admin, username1, pwd, "C=SE,O=EJBCA Sample,CN=" + username1, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
        try {
            endEntityManagementSession.addUser(admin, username2, pwd, "C=SE,O=EJBCA Sample,CN=" + username2, null, null, false,
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
        } catch (Exception e) {
            endEntityManagementSession.deleteUser(admin, username1);
            assertTrue("Database (mapping) is not case sensitive!", false);
        }
        EndEntityInformation endEntityInformation1 = endEntityAccessSession.findUser(admin, username1);
        EndEntityInformation endEntityInformation2 = endEntityAccessSession.findUser(admin, username2);
        assertFalse("Returned the same user object for different usernames.", endEntityInformation1.getUsername().equals(endEntityInformation2.getUsername()));
        endEntityManagementSession.deleteUser(admin, username1);
        endEntityManagementSession.deleteUser(admin, username2);
    }

    /**
     * Verify that there can't be two different users with the same username.
     */
    @Test
    public void testVerifySameUserName() throws Exception {
        String username = "sameun" + genRandomUserName();
        String pwd = genRandomPwd();
        endEntityManagementSession.addUser(admin, username, pwd, "C=SE,O=EJBCA Sample,CN=" + username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
        boolean ok = true;
        try {
            endEntityManagementSession.addUser(admin, username, pwd, "C=SE,O=EJBCA Sample,CN=" + username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
            ok = false;
        } catch (Exception e) {
        }
        try {
            endEntityManagementSession.deleteUser(admin, username);
        } catch (Exception e) {
            log.error("Delete failed: ", e);
            ok = false;
        }
        assertTrue("Two user with the same name were allowed!", ok);
    }
}
