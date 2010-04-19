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
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.TestTools;
import org.ejbca.util.dn.DnComponents;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserDataTest extends TestCase {

    private static final Logger log = Logger.getLogger(UserDataTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final int caid = TestTools.getTestCAId();

    private static String username;
    private static String username1;
    private static String pwd;
    private static String pwd1;

    /** variable used to hold a flag value so we can reset it after we have done the tests */
    private static boolean gcEELimitations;
    
    /**
     * Creates a new TestUserData object.
     */
    public UserDataTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);

        return username;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";

        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }

        log.debug("Generated random pwd: password=" + password);

        return password;
    } // genRandomPwd


    public void test00SetEnableEndEntityProfileLimitations() throws Exception {
        // Global configuration must have "Enable End Entity Profile Limitations" set to true in order for 
    	// the request counter tests to pass, we check if we are allowed to set this value or not
    	// The value is reset to whatever it was from the beginning in the last "clean up" test.
        GlobalConfiguration gc = TestTools.getRaAdminSession().loadGlobalConfiguration(admin);
        gcEELimitations = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(true);
        TestTools.getRaAdminSession().saveGlobalConfiguration(admin, gc);
    }
    
    public void test01CreateNewUser() throws Exception {
        log.trace(">test01CreateNewUser()");
        username = genRandomUserName();
        pwd = genRandomPwd();
        TestTools.getUserAdminSession().addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it!");
        log.trace("<test01CreateNewUser()");
    }

    public void test02LookupAndChangeUser() throws Exception {
        log.trace(">test02LookupAndChangeUser()");

        log.debug("username=" + username);
        UserDataVO data2 = TestTools.getUserAdminSession().findUser(admin,username);
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
        assertTrue("wrong pwd (foo123 works)", TestTools.getUserAdminSession().verifyPassword(admin,username,"foo123") == false);
        assertTrue("wrong pwd " + pwd, TestTools.getUserAdminSession().verifyPassword(admin,username,pwd));

        // Change DN
        TestTools.getUserAdminSession().changeUser(admin,username,"foo123","C=SE,O=AnaTom,OU=Engineering, CN="+username,null,username+"@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.debug("Changed it");
        log.trace("<test02LookupAndChangeUser()");
    }

    public void test03LookupChangedUser() throws Exception {
        log.trace(">test03LookupChangedUser()");

        UserDataVO data = TestTools.getUserAdminSession().findUser(admin,username);
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
        assertTrue("wrong pwd foo123", TestTools.getUserAdminSession().verifyPassword(admin,username,"foo123"));
        assertTrue("wrong pwd (" + pwd + " works)" + pwd, TestTools.getUserAdminSession().verifyPassword(admin,username,pwd) == false);

        // Use clear text pwd instead, new email, reverse DN again
        TestTools.getUserAdminSession().changeUser(admin,username,"foo234","C=SE,O=AnaTom,CN="+username,null,username+"@anatom.nu",true,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.trace("<test03LookupChangedUser()");
    }

    public void test03LookupChangedUser2() throws Exception {
        log.trace(">test03LookupChangedUser2()");

        UserDataVO data = TestTools.getUserAdminSession().findUser(admin,username);
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
        assertTrue("wrong pwd foo234", TestTools.getUserAdminSession().verifyPassword(admin,username,"foo234"));
        assertEquals("wrong clear pwd foo234", data.getPassword(), "foo234");
        assertTrue("wrong pwd (" + pwd + " works)", TestTools.getUserAdminSession().verifyPassword(admin,username,pwd) == false);
        
        TestTools.getUserAdminSession().setPassword(admin,username,"foo234");
        log.trace("<test03LookupChangedUser2()");
    }

    public void test04CreateNewUser() throws Exception {
        log.trace(">test04CreateNewUser()");
        username1 = genRandomUserName();
        pwd1 = genRandomPwd();
        TestTools.getUserAdminSession().addUser(admin,username1,pwd1,"C=SE,O=AnaTom,CN="+username1,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it again!");
        log.trace("<test04CreateNewUser()");
    }

    public void test05ListNewUser() throws Exception {
        log.trace(">test05ListNewUser()");

        Collection coll = TestTools.getUserAdminSession().findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        Iterator iter = coll.iterator();
        while (iter.hasNext()) {

            UserDataVO data = (UserDataVO) iter.next();
            log.debug("New user: " + data.getUsername() + ", " + data.getDN() + ", " + data.getEmail() + ", " + data.getStatus() + ", " + data.getType());
            TestTools.getUserAdminSession().setUserStatus(new Admin(Admin.TYPE_INTERNALUSER), data.getUsername(), UserDataConstants.STATUS_GENERATED);
        }

        Collection coll1 = TestTools.getUserAdminSession().findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        assertTrue("found NEW users though there should be none!", coll1.isEmpty());
        log.trace("<test05ListNewUser()");
    }

    public void test06RequestCounter() throws Exception {
        log.trace(">test06RequestCounter()");

        // Change already existing user to add extended information with counter
        UserDataVO user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setStatus(UserDataConstants.STATUS_GENERATED);
        TestTools.getUserAdminSession().changeUser(admin, user, false);
        
        // Default value should be 1, so it should return 0
        int counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);
        // Default value should be 1, so it should return 0
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now add extended information with allowed requests 2
        ExtendedInformation ei = new ExtendedInformation();
        int allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ei);
        boolean thrown = false;
        try {
            TestTools.getUserAdminSession().changeUser(admin, user, false);        	
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	thrown = true;
        }
        assertTrue(thrown);
        // decrease the value, since we use the empty end entity profile, the counter will not be used
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
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
            TestTools.getRaAdminSession().addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
            pid = TestTools.getRaAdminSession().getEndEntityProfileId(admin, "TESTREQUESTCOUNTER");
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
            TestTools.getUserAdminSession().changeUser(admin, user, false);        	
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	thrown = true;
        }
        assertTrue(thrown);
        // decrease the value
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again, default value when the counter is not used is 0        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now allow the counter
        EndEntityProfile ep = TestTools.getRaAdminSession().getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        // This time changeUser will be ok
        TestTools.getUserAdminSession().changeUser(admin, user, false);
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(-1, counter);        
        // decrease the value again
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(-1, counter);  
        
        // Now disallow the counter, it will be deleted from the user
        ep = TestTools.getRaAdminSession().getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedinformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, null);
        user.setExtendedinformation(ei);
        TestTools.getUserAdminSession().changeUser(admin, user, false);        	
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);

        // allow the counter 
        ep = TestTools.getRaAdminSession().getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        ei = user.getExtendedinformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");
        user.setExtendedinformation(ei);
        user.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user, false);
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(-1, counter);  

        // test setuserstatus it will re-set the counter
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        ep = TestTools.getRaAdminSession().getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(2, counter);
        // decrease the value again        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(0, counter);        
        // decrease the value again
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(-1, counter);
        
        // test setuserstatus again it will not re-set the counter if it is already new
        ep = TestTools.getRaAdminSession().getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        TestTools.getRaAdminSession().changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(-1, counter);

        // Also changeUser to new from something else will re-set status, if ei value is 0
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");        
        user.setExtendedinformation(ei);
        user.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user, false);
        // decrease the value        
        counter = TestTools.getUserAdminSession().decRequestCounter(admin, username);
        assertEquals(2, counter);
        
        // Test set and re-set logic
        
        // The profile has 3 as default value, if I change user with status to generated and value 2 it should be set as that
        UserDataVO user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        String value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("2", value);
        // If I change user with status to new and value 1 it should be set as that
        ei = new ExtendedInformation();
        allowedrequests = 1;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I set status to new again, with noting changed, nothing should change
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // The same when I change the user
        user1.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to generated, nothing should happen
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("1", value);
        // If I change the status to new from generated the default value should be used
        TestTools.getUserAdminSession().setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // It should be possible to simply set the value to 0
        ei = new ExtendedInformation();
        allowedrequests = 0;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user1.setExtendedinformation(ei);
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Changing again to new, with 0 passed in will set the default value
        user1.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("3", value);
        // Set back to 0
        user1.setStatus(UserDataConstants.STATUS_GENERATED);
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "0");
        user1.setExtendedinformation(ei);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertEquals("0", value);
        // Setting with null value will always remove the request counter
        user1.setExtendedinformation(null);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        TestTools.getUserAdminSession().changeUser(admin, user1, false);
        user1 = TestTools.getUserAdminSession().findUser(admin, user.getUsername());
        ei = user1.getExtendedinformation();
        value = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        assertNull(value);
        
        log.trace("<test06RequestCounter()");
    }

    /**
     * Cleans up after test JUnit tests, i.e. deletes users and CAs that we created and resets any configuration changes.
     *
     * @throws Exception on fatal error
     */
    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");

        // Reset the value of "EnableEndEntityProfileLimitations" to whatever it was before we ran test00SetEnableEndEntityProfileLimitations
        GlobalConfiguration gc = TestTools.getRaAdminSession().loadGlobalConfiguration(admin);
        gc.setEnableEndEntityProfileLimitations(gcEELimitations);
        TestTools.getRaAdminSession().saveGlobalConfiguration(admin, gc);

        // Delete test users we created
        try {        	
            TestTools.getUserAdminSession().deleteUser(admin,username);
        } catch (Exception e) { /* ignore */ }
        try {        	
            TestTools.getUserAdminSession().deleteUser(admin,username1);
        } catch (Exception e) { /* ignore */ }
        try {        	
            TestTools.getRaAdminSession().removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");
        } catch (Exception e) { /* ignore */ }

        // Delete any Test CA we created
        TestTools.removeTestCA();
        log.trace("<test99CleanUp()");
    }
}
