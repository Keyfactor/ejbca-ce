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

import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.util.InterfaceCache;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserPasswordExpireTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(UserPasswordExpireTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private int caid = getTestCAId();

    private static String username;
    private static String pwd;

    private ServiceSessionRemote serviceSession = InterfaceCache.getServiceSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    /**
     * Creates a new TestUserPasswordExpire object.
     * 
     * @param name
     *            DOCUMENT ME!
     */
    public UserPasswordExpireTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", createTestCA());
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    public void test01ExpireUserPassword() throws Exception {
        log.trace(">test01CreateNewUser()");

        // Create a new user
        username = genRandomUserName();
        pwd = genRandomPwd();
        userAdminSession.addUser(admin, username, pwd, "C=SE,O=AnaTom,CN=" + username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_INVALID, SecConst.TOKEN_SOFT_PEM, 0, caid);
        log.debug("created user: " + username);

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

        serviceSession.addService(admin, "TestUserPasswordService", config);
        serviceSession.activateServiceTimer(admin, "TestUserPasswordService");

        // The service will run...
        Thread.sleep(5000);

        // Now the user will not have been expired
        UserDataVO data = userAdminSession.findUser(admin, username);
        assertNotNull("User we have added can not be found", data);
        assertEquals(UserDataConstants.STATUS_NEW, data.getStatus());

        // Change the service to expire user after 5 seconds instead of after 5
        // hours
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        // Include a dummy CA so we can see that the query works with checking
        // several CAs
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid) + ";45");
        config.setWorkerProperties(workerprop);
        serviceSession.changeService(admin, "TestUserPasswordService", config, false);

        // The service will run...since there is a random delay of 30 seconds we
        // have to wait a long time
        Thread.sleep(35000);

        // Now the user will be expired
        data = userAdminSession.findUser(admin, username);
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
        userAdminSession.deleteUser(admin, username);
        log.debug("Removed user: " + username);
        serviceSession.removeService(admin, "TestUserPasswordService");
        log.debug("Removed service: TestUserPasswordService");
        removeTestCA();
        log.debug("Removed test CA");
        log.trace("<test99CleanUp()");
    }
}
