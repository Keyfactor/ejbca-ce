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

package org.ejbca.core.ejb.ra;

import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.dn.DnComponents;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserDataTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(UserDataTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private int caid = getTestCAId();

    private static String username;
    private static String username1;
    private static String pwd;
    private static String pwd1;

    /** variable used to hold a flag value so we can reset it after we have done the tests */
    private static boolean gcEELimitations;
    
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    
    /**
     * Creates a new TestUserData object.
     */
    public UserDataTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", createTestCA());
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    public void test00SetEnableEndEntityProfileLimitations() throws Exception {
        // Global configuration must have "Enable End Entity Profile Limitations" set to true in order for 
    	// the request counter tests to pass, we check if we are allowed to set this value or not
    	// The value is reset to whatever it was from the beginning in the last "clean up" test.
        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(admin);
        gcEELimitations = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(true);
        raAdminSession.saveGlobalConfiguration(admin, gc);
    }
    
    public void test01CreateNewUser() throws Exception {
        log.trace(">test01CreateNewUser()");
        username = genRandomUserName();
        pwd = genRandomPwd();
        userAdminSession.addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it!");
        log.trace("<test01CreateNewUser()");
    }

    public void test02LookupAndChangeUser() throws Exception {
        log.trace(">test02LookupAndChangeUser()");

        log.debug("username=" + username);
        UserDataVO data2 = userAdminSession.findUser(admin,username);
        log.debug("found by key! =" + data2);
        log.debug("username=" + data2.getUsername());
        assertTrue("wrong username", data2.getUsername().equals(username));
        log.debug("subject=" + data2.getDN());
        assertTrue("wrong DN", data2.getDN().indexOf(username) != -1);
        log.debug("email=" + data2.getEmail());
        assertNull("wrong email", data2.getEmail());
        log.debug("status=" + data2.getStatus());
        assertTrue("wrong status", data2.getStatus() == UserDataConstants.STATUS_NEW);
        log.debug("type=" + data2.getType());
        assertTrue("wrong type", data2.getType() == SecConst.USER_INVALID);
        assertTrue("wrong pwd (foo123 works)", userAdminSession.verifyPassword(admin,username,"foo123") == false);
        assertTrue("wrong pwd " + pwd, userAdminSession.verifyPassword(admin,username,pwd));

        // Change DN
        userAdminSession.changeUser(admin,username,"foo123","C=SE,O=AnaTom,OU=Engineering, CN="+username,null,username+"@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.debug("Changed it");
        log.trace("<test02LookupAndChangeUser()");
    }

    public void test03LookupChangedUser() throws Exception {
        log.trace(">test03LookupChangedUser()");

        UserDataVO data = userAdminSession.findUser(admin,username);
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
        assertTrue("wrong status", data.getStatus() == UserDataConstants.STATUS_GENERATED);
        log.debug("type=" + data.getType());
        assertTrue("wrong type", data.getType() == SecConst.USER_ENDUSER);
        assertTrue("wrong pwd foo123", userAdminSession.verifyPassword(admin,username,"foo123"));
        assertTrue("wrong pwd (" + pwd + " works)" + pwd, userAdminSession.verifyPassword(admin,username,pwd) == false);

        // Use clear text pwd instead, new email, reverse DN again
        userAdminSession.changeUser(admin,username,"foo234","C=SE,O=AnaTom,CN="+username,null,username+"@anatom.nu",true,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.trace("<test03LookupChangedUser()");
    }

    public void test03LookupChangedUser2() throws Exception {
        log.trace(">test03LookupChangedUser2()");

        UserDataVO data = userAdminSession.findUser(admin,username);
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
        assertTrue("wrong status", data.getStatus() == UserDataConstants.STATUS_GENERATED);
        log.debug("type=" + data.getType());
        assertTrue("wrong type", data.getType() == SecConst.USER_ENDUSER);
        assertTrue("wrong pwd foo234", userAdminSession.verifyPassword(admin,username,"foo234"));
        assertEquals("wrong clear pwd foo234", data.getPassword(), "foo234");
        assertTrue("wrong pwd (" + pwd + " works)", userAdminSession.verifyPassword(admin,username,pwd) == false);
        
        userAdminSession.setPassword(admin,username,"foo234");
        log.trace("<test03LookupChangedUser2()");
    }

    public void test04CreateNewUser() throws Exception {
        log.trace(">test04CreateNewUser()");
        username1 = genRandomUserName();
        pwd1 = genRandomPwd();
        userAdminSession.addUser(admin,username1,pwd1,"C=SE,O=AnaTom,CN="+username1,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it again!");
        log.trace("<test04CreateNewUser()");
    }

    public void test05ListNewUser() throws Exception {
        log.trace(">test05ListNewUser()");

        Collection<UserDataVO> coll = userAdminSession.findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        Iterator<UserDataVO> iter = coll.iterator();
        while (iter.hasNext()) {

            UserDataVO data = iter.next();
            log.debug("New user: " + data.getUsername() + ", " + data.getDN() + ", " + data.getEmail() + ", " + data.getStatus() + ", " + data.getType());
            userAdminSession.setUserStatus(new Admin(Admin.TYPE_INTERNALUSER), data.getUsername(), UserDataConstants.STATUS_GENERATED);
        }

        Collection<UserDataVO> coll1 = userAdminSession.findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        assertTrue("found NEW users though there should be none!", coll1.isEmpty());
        log.trace("<test05ListNewUser()");
    }

    public void test06RequestCounter() throws Exception {
        log.trace(">test06RequestCounter()");

        // Change already existing user to add extended information with counter
        UserDataVO user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setStatus(UserDataConstants.STATUS_GENERATED);
        userAdminSession.changeUser(admin, user, false);
        
        // Default value should be 1, so it should return 0
        int counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // Default value should be 1, so it should return 0
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now add extended information with allowed requests 2
        ExtendedInformation ei = new ExtendedInformation();
        int allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ei);
        boolean thrown = false;
        try {
            userAdminSession.changeUser(admin, user, false);        	
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	thrown = true;
        }
        // This requires "Enable end entity profile limitations" to be checked in admin GUI->System configuration
        assertTrue(thrown);
        // decrease the value, since we use the empty end entity profile, the counter will not be used
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        
        
        // Test that it works correctly with end entity profiles using the counter
        int pid = 0;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.addField(DnComponents.COMMONNAME);
            profile.setValue(EndEntityProfile.AVAILCAS,0,""+caid);
            profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
            endEntityProfileSession.addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
            pid = endEntityProfileSession.getEndEntityProfileId(admin, "TESTREQUESTCOUNTER");
        } catch (EndEntityProfileExistsException pee) {
        	assertTrue("Can not create end entity profile", false);
        }
        // Now add extended information with allowed requests 2
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));        
        user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, pid, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ei);
        thrown = false;
        try {
            userAdminSession.changeUser(admin, user, false);        	
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	thrown = true;
        }
        assertTrue(thrown);
        // decrease the value
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again, default value when the counter is not used is 0        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now allow the counter
        EndEntityProfile ep = endEntityProfileSession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        // This time changeUser will be ok
        userAdminSession.changeUser(admin, user, false);
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(-1, counter);        
        // decrease the value again
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(-1, counter);  
        
        // Now disallow the counter, it will be deleted from the user
        ep = endEntityProfileSession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedinformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, null);
        user.setExtendedinformation(ei);
        userAdminSession.changeUser(admin, user, false);        	
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // allow the counter 
        ep = endEntityProfileSession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedinformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");
        user.setExtendedinformation(ei);
        user.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user, false);
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(-1, counter);  

        // test setuserstatus it will re-set the counter
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        ep = endEntityProfileSession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(2, counter);
        // decrease the value again        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // test setuserstatus again it will not re-set the counter if it is already new
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        assertEquals(1, counter);
        // decrease the value again
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(0, counter); // sets status to generated
        // decrease the value again
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(-1, counter);
        
        // test setuserstatus again it will re-set the counter since status is generated
        ep = endEntityProfileSession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(2, counter);

        // Also changeUser to new from something else will re-set status, if ei value is 0
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");        
        user.setExtendedinformation(ei);
        user.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user, false);
        // decrease the value        
        counter = userAdminSession.decRequestCounter(admin, username);
        assertEquals(2, counter);
        
        // Test set and re-set logic
        
        // The profile has 3 as default value, if I change user with status to generated and value 2 it should be set as that
        UserDataVO user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        String value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("2", value);
        // If I change user with status to new and value 1 it should be set as that
        ei = new ExtendedInformation();
        allowedrequests = 1;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I set status to new again, with noting changed, nothing should change
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // The same when I change the user
        user1.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to generated, nothing should happen
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to new from generated the default value should be used
        userAdminSession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // It should be possible to simply set the value to 0
        ei = new ExtendedInformation();
        allowedrequests = 0;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Changing again to new, with 0 passed in will set the default value
        user1.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // Set back to 0
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");
        user1.setExtendedinformation(ei);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Setting with null value will always remove the request counter (the whole extendedinformatin actually)
        user1.setExtendedinformation(null);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user1, false);
        user1 = userAdminSession.findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        assertNull(ei);
        
        log.trace("<test06RequestCounter()");
    }

    public void test07EndEntityProfileMappings() throws Exception {
    	// Add a couple of profiles and verify that the mappings and get functions work
        EndEntityProfile profile1 = new EndEntityProfile();
        profile1.setPrinterName("foo");
        endEntityProfileSession.addEndEntityProfile(admin, "TESTEEPROFCACHE1", profile1);
        EndEntityProfile profile2 = new EndEntityProfile();
        profile2.setPrinterName("bar");
        endEntityProfileSession.addEndEntityProfile(admin, "TESTEEPROFCACHE2", profile2);
        int pid = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE1"); 
        String name = endEntityProfileSession.getEndEntityProfileName(admin, pid);
        int pid1 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE1"); 
        String name1 = endEntityProfileSession.getEndEntityProfileName(admin, pid1);
        assertEquals(pid, pid1);
        assertEquals(name, name1);
        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(admin, pid);
        assertEquals("foo", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(admin, name);
        assertEquals("foo", profile.getPrinterName());

        int pid2 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE2"); 
        String name2 = endEntityProfileSession.getEndEntityProfileName(admin, pid2);
        profile = endEntityProfileSession.getEndEntityProfile(admin, pid2);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(admin, name2);
        assertEquals("bar", profile.getPrinterName());

        // flush caches and make sure it is read correctly again
        endEntityProfileSession.flushProfileCache();

        int pid3 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE1"); 
        String name3 = endEntityProfileSession.getEndEntityProfileName(admin, pid3);
        assertEquals(pid1, pid3);
        assertEquals(name1, name3);
        profile = endEntityProfileSession.getEndEntityProfile(admin, pid3);
        assertEquals("foo", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(admin, name3);
        assertEquals("foo", profile.getPrinterName());

        int pid4 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE2"); 
        String name4 = endEntityProfileSession.getEndEntityProfileName(admin, pid4);
        assertEquals(pid2, pid4);
        assertEquals(name2, name4);
        profile = endEntityProfileSession.getEndEntityProfile(admin, pid4);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(admin, name4);
        assertEquals("bar", profile.getPrinterName());

        // Remove a profile and make sure it is not cached still
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTEEPROFCACHE1");
        profile = endEntityProfileSession.getEndEntityProfile(admin, pid1);
        assertNull(profile);
        int pid5 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE1");
        assertEquals(0, pid5);
        String name5 = endEntityProfileSession.getEndEntityProfileName(admin, pid5);
        assertNull(name5);

        // But the other, non-removed profile should still be there
        int pid6 = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEEPROFCACHE2"); 
        String name6 = endEntityProfileSession.getEndEntityProfileName(admin, pid6);
        assertEquals(pid2, pid6);
        assertEquals(name2, name6);
        profile = endEntityProfileSession.getEndEntityProfile(admin, pid6);
        assertEquals("bar", profile.getPrinterName());
        profile = endEntityProfileSession.getEndEntityProfile(admin, name6);
        assertEquals("bar", profile.getPrinterName());        
    } // test07EndEntityProfileMappings

    /**
     * Test of the cache of end entity profiles. This test depends on the default cache time of 1 second being used.
     * If you changed this config, eeprofiles.cachetime, this test may fail. 
     */
    public void test08EndEntityProfileCache() throws Exception {
    	// First a check that we have the correct configuration, i.e. default
    	long cachetime = EjbcaConfiguration.getCacheEndEntityProfileTime();
    	assertEquals(1000, cachetime);
    	// Make sure profile has the right value from the beginning
        EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(admin, "TESTEEPROFCACHE2");
        eep.setAllowMergeDnWebServices(false);
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTEEPROFCACHE2", eep);
    	// Read profile
        eep = endEntityProfileSession.getEndEntityProfile(admin, "TESTEEPROFCACHE2");
        boolean value = eep.getAllowMergeDnWebServices();
        assertFalse(value);

        // Flush caches to reset cache timeout
        endEntityProfileSession.flushProfileCache();
    	// Change profile, not flushing cache
    	eep.setAllowMergeDnWebServices(true);
    	endEntityProfileSession.internalChangeEndEntityProfileNoFlushCache(admin, "TESTEEPROFCACHE2", eep);

    	// Wait 2 seconds and try again, now the cache should have been updated
    	Thread.sleep(2000);
        eep = endEntityProfileSession.getEndEntityProfile(admin, "TESTEEPROFCACHE2");
        value = eep.getAllowMergeDnWebServices();
        assertTrue(value);

        // Changing using the regular method however should immediately flush the cache
    	eep.setAllowMergeDnWebServices(false);
    	endEntityProfileSession.changeEndEntityProfile(admin, "TESTEEPROFCACHE2", eep);
        eep = endEntityProfileSession.getEndEntityProfile(admin, "TESTEEPROFCACHE2");
        value = eep.getAllowMergeDnWebServices();
        assertFalse(value);
    }

    /**
     * Verify that there can be two different users with the same name, but in different case.  
     */
    public void test09VerifyUserNameCaseSensitivity() throws Exception {
    	String rnd = "sens" + genRandomUserName();
        String username1 = rnd.toLowerCase();
        String username2 = rnd.toUpperCase();;
        String pwd = genRandomPwd();
        userAdminSession.addUser(admin, username1, pwd, "C=SE,O=EJBCA Sample,CN="+username1, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_INVALID, SecConst.TOKEN_SOFT_PEM, 0, caid);
        try {
        	userAdminSession.addUser(admin, username2, pwd, "C=SE,O=EJBCA Sample,CN="+username2, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_INVALID, SecConst.TOKEN_SOFT_PEM, 0, caid);
        } catch (Exception e) {
            userAdminSession.deleteUser(admin, username1);
            assertTrue("Database (mapping) is not case sensitive!", false);
        }
        UserDataVO userDataVO1 = userAdminSession.findUser(admin, username1);
        UserDataVO userDataVO2 = userAdminSession.findUser(admin, username2);
        assertFalse("Returned the same user object for different usernames.", userDataVO1.getUsername().equals(userDataVO2.getUsername()));
        userAdminSession.deleteUser(admin, username1);
        userAdminSession.deleteUser(admin, username2);
    }

    /**
     * Verify that there can't be two different users with the same username.  
     */
    public void test10VerifySameUserName() throws Exception {
        String username = "sameun" + genRandomUserName();
        String pwd = genRandomPwd();
        userAdminSession.addUser(admin, username, pwd, "C=SE,O=EJBCA Sample,CN="+username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_INVALID, SecConst.TOKEN_SOFT_PEM, 0, caid);
        boolean ok = true;
        try {
        	userAdminSession.addUser(admin, username, pwd, "C=SE,O=EJBCA Sample,CN="+username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_INVALID, SecConst.TOKEN_SOFT_PEM, 0, caid);
        	ok = false;
        } catch (Exception e) {
        }
        try {
            userAdminSession.deleteUser(admin, username);
        } catch (Exception e) {
        	log.error("Delete failed: ", e);
        	ok = false;
        }
        assertTrue("Two user with the same name were allowed!", ok);
    }
    
    public void test11UserPassword() throws Exception {
    	UserData data = new UserData();
    	data.setPassword("foo123");
    	String hash = data.getPasswordHash();
    	// Check that it by default generates a strong bcrypt password hash
    	assertTrue(hash.startsWith("$2"));
    	assertFalse(data.comparePassword("bar123"));
    	assertTrue(data.comparePassword("foo123"));
    	// Set the same password again, it should be another hash this time
    	data.setPassword("foo123");
    	String hash1 = data.getPasswordHash();
    	assertTrue(hash1.startsWith("$2"));
    	assertFalse(hash1.equals(hash));

    	// Now check that we can still use old password hashes transparently usgin the old fixed sha1 hash of foo123
    	data.setPasswordHash("3b303d8b0364d9265c06adc8584258376150c9b5");
    	assertEquals("3b303d8b0364d9265c06adc8584258376150c9b5", data.getPasswordHash());
    	assertFalse(data.comparePassword("bar123"));
    	assertTrue(data.comparePassword("foo123"));

    	// Check that set clear text password works as well
    	data.setOpenPassword("primekey");
    	hash = data.getPasswordHash();
    	// Check that it by default generates a strong bcrypt password hash
    	assertTrue(hash.startsWith("$2"));
    	assertFalse(data.comparePassword("foo123123"));
    	assertTrue(data.comparePassword("primekey"));
    	assertEquals("primekey", data.getClearPassword());

    }

    	
    /**
     * Cleans up after test JUnit tests, i.e. deletes users and CAs that we created and resets any configuration changes.
     *
     * @throws Exception on fatal error
     */
    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");

        // Reset the value of "EnableEndEntityProfileLimitations" to whatever it was before we ran test00SetEnableEndEntityProfileLimitations
        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(admin);
        gc.setEnableEndEntityProfileLimitations(gcEELimitations);
        raAdminSession.saveGlobalConfiguration(admin, gc);

        // Delete test users we created
        try {        	
            userAdminSession.deleteUser(admin,username);
        } catch (Exception e) { /* ignore */ }
        try {        	
            userAdminSession.deleteUser(admin,username1);
        } catch (Exception e) { /* ignore */ }
        try {        	
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");
        } catch (Exception e) { /* ignore */ }
        try {        	
        	endEntityProfileSession.removeEndEntityProfile(admin, "TESTEEPROFCACHE1");
        } catch (Exception e) { /* ignore */ }
        try {        	
        	endEntityProfileSession.removeEndEntityProfile(admin, "TESTEEPROFCACHE2");
        } catch (Exception e) { /* ignore */ }

        // Delete any Test CA we created
        removeTestCA();
        log.trace("<test99CleanUp()");
    }
}
