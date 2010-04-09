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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.util.TestTools;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserPasswordExpireTest extends TestCase {

    private static final Logger log = Logger.getLogger(UserPasswordExpireTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final int caid = TestTools.getTestCAId();

    private static String username;
    private static String pwd;

    /**
     * Creates a new TestUserPasswordExpire object.
     *
     * @param name DOCUMENT ME!
     */
    public UserPasswordExpireTest(String name) {
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


    /** Add a new user and an expire service. Test that the service expires the users password
     *
     */
    public void test01ExpireUserPassword() throws Exception {
        log.trace(">test01CreateNewUser()");
        
        // Create a new user
        username = genRandomUserName();
        pwd = genRandomPwd();
        TestTools.getUserAdminSession().addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0,caid);
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
		workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
		workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
		workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid));
		workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "5");
		workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_HOURS);
		config.setWorkerProperties(workerprop);
		
		TestTools.getServiceSession().addService(admin, "TestUserPasswordService", config);
        TestTools.getServiceSession().activateServiceTimer(admin, "TestUserPasswordService");
        
        // The service will run...
        Thread.sleep(5000);
        
        // Now the user will not have been expired
        UserDataVO data = TestTools.getUserAdminSession().findUser(admin,username);
        assertNotNull("User we have added can not be found", data);
        assertEquals(UserDataConstants.STATUS_NEW, data.getStatus());

        // Change the service to expire user after 5 seconds instead of after 5 hours
		workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        // Include a dummy CA so we can see that the query works with checking several CAs
		workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid)+";45");
		config.setWorkerProperties(workerprop);
        TestTools.getServiceSession().changeService(admin, "TestUserPasswordService", config, false);
        
        // The service will run...since there is a random delay of 30 seconds we have to wait a long time
        Thread.sleep(35000);
        
        // Now the user will be expired
        data = TestTools.getUserAdminSession().findUser(admin,username);
        assertNotNull("User we have added can not be found", data);
        assertEquals(UserDataConstants.STATUS_GENERATED, data.getStatus());
        
        log.trace("<test01CreateNewUser()");
    }


    /**
     * Remove all data stored by JUnit tests
     *
     */
    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");
        TestTools.getUserAdminSession().deleteUser(admin,username);
        log.debug("Removed user: "+username);
        TestTools.getServiceSession().removeService(admin, "TestUserPasswordService");
        log.debug("Removed service: TestUserPasswordService");
        TestTools.removeTestCA();
        log.debug("Removed test CA");
        log.trace("<test99CleanUp()");
    }
}
