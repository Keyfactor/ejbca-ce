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

package org.ejbca.core.model.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** Tests the EndEntityInformation entity bean and some parts of EndEntityManagementSession.
 *
 * @version $Id$
 */
public class UserPasswordExpireTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(UserPasswordExpireTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserPasswordExpireTest"));
    private int caid = getTestCAId();

    private static final String USERNAME = "UserPasswordExpireTestUser";
    private static final String PWD = "foo123";

    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        endEntityManagementSession.deleteUser(admin, USERNAME);
        log.debug("Removed user: " + USERNAME);
        serviceSession.removeService(admin, "TestUserPasswordService");
        log.debug("Removed service: TestUserPasswordService");
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    @Test
    public void test01ExpireUserPassword() throws Exception {
        log.trace(">test01CreateNewUser()");

        // Create a new user
        endEntityManagementSession.addUser(admin, USERNAME, PWD, "C=SE,O=AnaTom,CN=" + USERNAME, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.INVALID.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
        log.debug("created user: " + USERNAME);

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

        // Now the user will not have been expired
        EndEntityInformation data = endEntityAccessSession.findUser(admin, USERNAME);
        assertNotNull("User we have added can not be found", data);
        assertEquals(EndEntityConstants.STATUS_NEW, data.getStatus());

        // Change the service to expire user after 5 seconds instead of after 5
        // hours
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        // Include a dummy CA so we can see that the query works with checking
        // several CAs
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, caid + ";45");
        config.setWorkerProperties(workerprop);
        serviceSession.changeService(admin, "TestUserPasswordService", config, false);

        Thread.sleep(10000);

        // Now the user will be expired
        data = endEntityAccessSession.findUser(admin, USERNAME);
        assertNotNull("User we have added can not be found", data);
        assertEquals(EndEntityConstants.STATUS_GENERATED, data.getStatus());

        log.trace("<test01CreateNewUser()");
    }
}
