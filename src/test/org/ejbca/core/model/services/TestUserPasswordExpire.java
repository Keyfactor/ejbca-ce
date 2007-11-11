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

package org.ejbca.core.model.services;

import java.util.Date;
import java.util.Properties;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.services.IServiceSessionHome;
import org.ejbca.core.ejb.services.IServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorker;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;




/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id: TestUserPasswordExpire.java,v 1.1 2007-11-11 07:58:00 anatom Exp $
 */
public class TestUserPasswordExpire extends TestCase {

    private static Logger log = Logger.getLogger(TestUserPasswordExpire.class);
    private static Context ctx;
    private static IUserAdminSessionRemote usersession;
    private static IServiceSessionRemote servicesession;
    private static String username;
    private static String pwd;
    private static int caid;
    private static Admin admin = null;

    /**
     * Creates a new TestUserPasswordExpire object.
     *
     * @param name DOCUMENT ME!
     */
    public TestUserPasswordExpire(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();

        caid = "CN=TEST".hashCode();

        Object obj = ctx.lookup(IUserAdminSessionHome.JNDI_NAME);
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        obj = ctx.lookup(IServiceSessionHome.JNDI_NAME);
        IServiceSessionHome servicehome = (IServiceSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IServiceSessionHome.class);
        usersession = userhome.create();
        servicesession = servicehome.create();
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


    /** Add a new user and an expire service. Test that the service expires the users password
     *
     */
    public void test01ExpireUserPassword() throws Exception {
        log.debug(">test01CreateNewUser()");
        
        // Create a new user
        username = genRandomUserName();
        pwd = genRandomPwd();
        usersession.addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
        log.debug("created user: "+username);
        
        // Create a new UserPasswordExpireService
		ServiceConfiguration config = new ServiceConfiguration();
		config.setActive(true);
		config.setDescription("This is a description");
		// No mailsending for this Junit test service
		config.setActionClassPath(NoAction.class.getName());
		config.setActionProperties(null); 
		config.setIntervalClassPath(PeriodicalInterval.class.getName());
		Properties intervalprop = new Properties();
		// Run the service every 3:rd second
		intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
		intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
		config.setIntervalProperties(intervalprop);
		config.setWorkerClassPath(UserPasswordExpireWorker.class.getName());
		Properties workerprop = new Properties();
		workerprop.setProperty(EmailSendingWorker.PROP_SENDTOADMINS, "FALSE");
		workerprop.setProperty(EmailSendingWorker.PROP_SENDTOENDUSERS, "FALSE");
		workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid));
		workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "5");
		workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_HOURS);
		config.setWorkerProperties(workerprop);
		
        servicesession.addService(admin, "TestUserPasswordService", config);
        servicesession.activateServiceTimer(admin, "TestUserPasswordService");
        
        // The service will run...
        Thread.sleep(5000);
        
        // Now the user will not have been expired
        UserDataVO data = usersession.findUser(admin,username);
        assertNotNull("User we have added can not be found", data);
        assertEquals(UserDataConstants.STATUS_NEW, data.getStatus());

        // Change the service to expire user after 5 seconds instead of after 5 hours
		workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        // Include a dummy CA so we can see that the questy works with checking several CAs
		workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid)+";45");
		config.setWorkerProperties(workerprop);
        servicesession.changeService(admin, "TestUserPasswordService", config);
        
        // The service will run...
        Thread.sleep(5000);
        
        // Now the user will be expired
        data = usersession.findUser(admin,username);
        assertNotNull("User we have added can not be found", data);
        assertEquals(UserDataConstants.STATUS_GENERATED, data.getStatus());
        
        log.debug("<test01CreateNewUser()");
    }


    /**
     * Remove all data stored by JUnit tests
     *
     */
    public void test99CleanUp() throws Exception {
        log.debug(">test99CleanUp()");

        usersession.deleteUser(admin,username);
        log.debug("Removed user: "+username);
        servicesession.removeService(admin, "TestUserPasswordService");
        log.debug("Removed service: TestUserPasswordService");
        
        log.debug("<test99CleanUp()");
    }
}
