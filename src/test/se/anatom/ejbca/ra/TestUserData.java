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

package se.anatom.ejbca.ra;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.dn.DnComponents;




/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id: TestUserData.java,v 1.9 2008-01-03 12:52:40 anatom Exp $
 */
public class TestUserData extends TestCase {

    private static Logger log = Logger.getLogger(TestUserData.class);
    private static Context ctx;
    private static IUserAdminSessionRemote usersession;
    private static IRaAdminSessionRemote rasession;
    private static String username;
    private static String username1;
    private static String pwd;
    private static String pwd1;
    private static int caid;
    private static Admin admin = null;

    /**
     * Creates a new TestUserData object.
     *
     * @param name DOCUMENT ME!
     */
    public TestUserData(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();

        caid = "CN=TEST".hashCode();

        Object obj = ctx.lookup(IUserAdminSessionHome.JNDI_NAME);
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();
        obj = ctx.lookup(IRaAdminSessionHome.JNDI_NAME);
        IRaAdminSessionHome rahome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IRaAdminSessionHome.class);
        rasession = rahome.create();

        admin = new Admin(Admin.TYPE_INTERNALUSER);

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


    public void test01CreateNewUser() throws Exception {
        log.debug(">test01CreateNewUser()");
        username = genRandomUserName();
        pwd = genRandomPwd();
        usersession.addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it!");
        log.debug("<test01CreateNewUser()");
    }

    public void test02LookupAndChangeUser() throws Exception {
        log.debug(">test02LookupAndChangeUser()");

        log.debug("username=" + username);
        UserDataVO data2 = usersession.findUser(admin,username);
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
        assertTrue("wrong pwd (foo123 works)", usersession.verifyPassword(admin,username,"foo123") == false);
        assertTrue("wrong pwd " + pwd, usersession.verifyPassword(admin,username,pwd));

        // Change DN
        usersession.changeUser(admin,username,"foo123","C=SE,O=AnaTom,OU=Engineering, CN="+username,null,username+"@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.debug("Changed it");
        log.debug("<test02LookupAndChangeUser()");
    }

    public void test03LookupChangedUser() throws Exception {
        log.debug(">test03LookupChangedUser()");

        UserDataVO data = usersession.findUser(admin,username);
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
        assertTrue("wrong pwd foo123", usersession.verifyPassword(admin,username,"foo123"));
        assertTrue("wrong pwd (" + pwd + " works)" + pwd, usersession.verifyPassword(admin,username,pwd) == false);

        // Use clear text pwd instead, new email, reverse DN again
        usersession.changeUser(admin,username,"foo234","C=SE,O=AnaTom,CN="+username,null,username+"@anatom.nu",true,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_GENERATED,caid);
        log.debug("<test03LookupChangedUser()");
    }

    public void test03LookupChangedUser2() throws Exception {
        log.debug(">test03LookupChangedUser2()");

        UserDataVO data = usersession.findUser(admin,username);
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
        assertTrue("wrong pwd foo234", usersession.verifyPassword(admin,username,"foo234"));
        assertEquals("wrong clear pwd foo234", data.getPassword(), "foo234");
        assertTrue("wrong pwd (" + pwd + " works)", usersession.verifyPassword(admin,username,pwd) == false);
        
        usersession.setPassword(admin,username,"foo234");
        log.debug("<test03LookupChangedUser2()");
    }

    public void test04CreateNewUser() throws Exception {
        log.debug(">test04CreateNewUser()");
        username1 = genRandomUserName();
        pwd1 = genRandomPwd();
        usersession.addUser(admin,username1,pwd1,"C=SE,O=AnaTom,CN="+username1,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created it again!");
        log.debug("<test04CreateNewUser()");
    }

    public void test05ListNewUser() throws Exception {
        log.debug(">test05ListNewUser()");

        Object obj1 = ctx.lookup(IUserAdminSessionHome.JNDI_NAME);
        IUserAdminSessionHome adminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSessionRemote admin = adminhome.create();
        Collection coll = admin.findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        Iterator iter = coll.iterator();
        while (iter.hasNext()) {

            UserDataVO data = (UserDataVO) iter.next();
            log.debug("New user: " + data.getUsername() + ", " + data.getDN() + ", " + data.getEmail() + ", " + data.getStatus() + ", " + data.getType());
            admin.setUserStatus(new Admin(Admin.TYPE_INTERNALUSER), data.getUsername(), UserDataConstants.STATUS_GENERATED);
        }

        Collection coll1 = admin.findAllUsersByStatus(new Admin(Admin.TYPE_INTERNALUSER), UserDataConstants.STATUS_NEW);
        assertTrue("found NEW users though there should be none!", coll1.isEmpty());
        log.debug("<test05ListNewUser()");
    }

    public void test06RequestCounter() throws Exception {
        log.debug(">test06RequestCounter()");

        // Change already existing user to add extended information with counter
        UserDataVO user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT, 0, null);
        user.setStatus(UserDataConstants.STATUS_GENERATED);
        usersession.changeUser(admin, user, false);
        
        // Default value should be 1, so it should return 0
        int counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // Default value should be 1, so it should return 0
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now add extended information with allowed requests 2
        ExtendedInformation ei = new ExtendedInformation();
        int allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));        
        user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT, 0, ei);
        usersession.changeUser(admin, user, false);
        // decrease the value, since we use the empty end entity profile, the counter will not be used
        counter = usersession.decRequestCounter(admin, username);
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
            rasession.addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
            pid = rasession.getEndEntityProfileId(admin, "TESTREQUESTCOUNTER");
        } catch (EndEntityProfileExistsException pee) {
        	assertTrue("Can not create end entity profile", false);
        }
        // Now add extended information with allowed requests 2
        ei = new ExtendedInformation();
        allowedrequests = 2;
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));        
        user = new UserDataVO(username, "C=SE,O=AnaTom,CN="+username, caid, null, null, SecConst.USER_INVALID, pid, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT, 0, ei);
        usersession.changeUser(admin, user, false);
        // decrease the value
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again, default value when the counter is not used is 0        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // Now allow the counter
        EndEntityProfile ep = rasession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        rasession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        usersession.changeUser(admin, user, false);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(-1, counter);        
        // decrease the value again
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(-1, counter);  
        
        // Now disallow the counter, it will be deleted form the user
        ep = rasession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
        rasession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        usersession.changeUser(admin, user, false);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);

        // allow the counter 
        ep = rasession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"2");
        rasession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        usersession.changeUser(admin, user, false);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);
        // decrease the value again
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(-1, counter);  

        // test setuserstatus it will re-set the counter
        ep = rasession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        rasession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        usersession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(2, counter);
        // decrease the value again        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        // decrease the value again
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(0, counter);        
        // decrease the value again
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(-1, counter);
        
        // test setuserstatus again it will not re-set the counter if it is already new
        ep = rasession.getEndEntityProfile(admin, pid);
        ep.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        ep.setValue(EndEntityProfile.ALLOWEDREQUESTS,0,"3");
        rasession.changeEndEntityProfile(admin, "TESTREQUESTCOUNTER", ep);
        usersession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_NEW);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(-1, counter);

        // Also changeUser will re-set status
        usersession.setUserStatus(admin, user.getUsername(), UserDataConstants.STATUS_GENERATED);
        user.setStatus(UserDataConstants.STATUS_NEW);
        usersession.changeUser(admin, user, false);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(2, counter);

        // But not a second time
        usersession.changeUser(admin, user, false);
        // decrease the value        
        counter = usersession.decRequestCounter(admin, username);
        assertEquals(1, counter);
        
        log.debug("<test06RequestCounter()");
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void test99CleanUp() throws Exception {
        log.debug(">test99CleanUp()");

        try {        	
            usersession.deleteUser(admin,username);
        } catch (Exception e) { /* ignore */ }
        try {        	
            usersession.deleteUser(admin,username1);
        } catch (Exception e) { /* ignore */ }
        try {        	
            rasession.removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");
        } catch (Exception e) { /* ignore */ }
        log.debug("Removed it!");
        log.debug("<test99CleanUp()");
    }
}
