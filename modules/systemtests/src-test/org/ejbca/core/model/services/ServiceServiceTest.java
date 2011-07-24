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

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.services.ServiceSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.util.InterfaceCache;

/** 
 * Tests parts of the ServiceSession. The tests depends on the 
 * UserPasswordExpire functionality to have something to run with.
 *
 * @version $Id$
 */
public class ServiceServiceTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(ServiceServiceTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    
    private static final String NOT_THIS_HOST1 = "notthishost.nodomain";
    private static final String NOT_THIS_HOST2 = "notthishost2.nodomain";
    private static final String TEST01_SERVICE = "TestServiceService_Test01Service";
    private static final String TEST02_SERVICE = "TestServiceService_Test02Service";
    private static final String TEST03_SERVICE = "TestServiceService_Test03Service";
    private static final String TESTCA1 = "TestServiceService_TestCA1";
    private static final String TESTCA2 = "TestServiceService_TestCA2";
    private static final String TESTCA3 = "TestServiceService_TestCA3";

    private static Collection<String> usernames = new LinkedList<String>();
    private static Collection<String> services = Arrays.asList(TEST01_SERVICE, TEST02_SERVICE, TEST03_SERVICE);
    private static Collection<String> cas = Arrays.asList(TESTCA1, TESTCA2, TESTCA3);
    
    private UserAdminSession userAdminSession;
    private ServiceSession serviceSession;

    /**
     * Creates a new TestServiceService.
     * @param name of test suite.
     */
    public ServiceServiceTest(String name) {
        super(name);
        userAdminSession = InterfaceCache.getUserAdminSession();
        serviceSession = InterfaceCache.getServiceSession();
    }

    /**
     * Create test CA:s.
     * @throws Exception in case of error.
     */
    public void test00SetupDatabase() throws Exception {
    	createTestCA(TESTCA1);
    	createTestCA(TESTCA2);
    	createTestCA(TESTCA3);
    }
    
    /**
     * Tests that when a service is pinned to a set of nodes which includes 
     * this node, the service is executed on this node.
     * @throws Exception In case of error.
     */
    public void test01PinServiceToNodesIncludingThis() throws Exception {
        log.trace(">test01PinServiceToNodesIncludingThis()");
        
        final String username = genRandomUserName();
        usernames.add(username);
        final ServiceConfiguration config = createAServiceConfig(username, TESTCA1);
        
        // Pin this service to some nodes including this node
        final Set<String> thisHosts = getHostNames();
        final List<String> nodes = new LinkedList<String>();
        nodes.add(NOT_THIS_HOST1);
        nodes.addAll(thisHosts);
        nodes.add(NOT_THIS_HOST2);
		config.setPinToNodes(nodes.toArray(new String[0]));
        
        addAndActivateService(TEST01_SERVICE, config, TESTCA1);
        
        // The service will run...
        Thread.sleep(7*1000);
        
        assertTrue("Service should have run", hasServiceRun(username));
        
        log.trace("<test01PinServiceToNodesIncludingThis()");
    }
    
    /**
     * Tests that when a service is pinned to a set of nodes other than this 
     * node the service should not be executed.
     * @throws Exception In case of error.
     */
    public void test02PinServiceToOtherNodesOnly() throws Exception {
        log.trace(">test02PinServiceToOtherNodesOnly()");
        
        final String username = genRandomUserName();
        usernames.add(username);
        final ServiceConfiguration config = createAServiceConfig(username, TESTCA2);
        
        // Pin this service to some nodes NOT including this node
		config.setPinToNodes(new String[] { NOT_THIS_HOST1, NOT_THIS_HOST2 });
        
        addAndActivateService(TEST02_SERVICE, config, TESTCA2);
        
        // The service will run...
        Thread.sleep(7*1000);
        
        assertFalse("Service should not have run", hasServiceRun(username));
        
        log.trace("<test02PinServiceToOtherNodesOnly()");
    }
    
    /**
     * Tests that when a service is not pinned at all it will execute on this 
     * node (assuming this is the only node in the cluster).
     * @throws Exception In case of error.
     */
    public void test03NotPinnedService() throws Exception {
        log.trace(">test03NotPinnedService()");
        
        final String username = genRandomUserName();
        usernames.add(username);
        final ServiceConfiguration config = createAServiceConfig(username, TESTCA3);
        
        // Do not pin this service to any node - it should be allowed to 
        // execute on any
		config.setPinToNodes(new String[0]);
        
        addAndActivateService(TEST03_SERVICE, config, TESTCA3);
        
        // The service will run...
        Thread.sleep(7*1000);
        
        assertTrue("Service should have run", hasServiceRun(username));
        
        log.trace("<test03NotPinnedService()");
    }

    /**
     * Remove all data stored by JUnit tests.
     * @throws Exception In case of error.
     */
    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");
        for (String username : usernames) {
        	getUserAdminSession().deleteUser(admin, username);
        	log.debug("Removed user: " + username);
        }
        for (String service : services) {
        	getServiceSession().removeService(admin, service);
            log.debug("Removed service: " + service);
        }
        for (String caName : cas) {
        	removeTestCA(caName);
        	log.debug("Removed test CA: " + caName);
        }
        log.trace("<test99CleanUp()");
    }

    private ServiceConfiguration createAServiceConfig(final String username, final String caName) throws Exception {
    	// Create a new user
        final String pwd = genRandomPwd();
        getUserAdminSession().addUser(admin,username,pwd,"C=SE,O=AnaTom,CN="+username,null,null,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_INVALID,SecConst.TOKEN_SOFT_PEM,0, getTestCAId(caName));
        log.debug("created user: "+username);
        
        // Create a new UserPasswordExpireService
		ServiceConfiguration config = new ServiceConfiguration();
		config.setActive(true);
		config.setDescription("This is a description");
		// No mailsending for this Junit test service
		config.setActionClassPath(NoAction.class.getName());
		config.setActionProperties(null); 
		config.setIntervalClassPath(PeriodicalInterval.class.getName());
		return config;
    }

    private void addAndActivateService(final String name, final ServiceConfiguration config, final String caName) throws Exception {
		Properties intervalprop = new Properties();
		// Run the service every 3:rd second
		intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
		intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
		config.setIntervalProperties(intervalprop);
		config.setWorkerClassPath(UserPasswordExpireWorker.class.getName());
		Properties workerprop = new Properties();
		workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
		workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
		workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(getTestCAId(caName)));
		workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "5");
		workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
		config.setWorkerProperties(workerprop);
		
		getServiceSession().addService(admin, name, config);
        getServiceSession().activateServiceTimer(admin, name);
    }
    
    private boolean hasServiceRun(final String username) throws Exception {
    	// Now the user will be expired
    	final boolean result;
        final UserDataVO data = getUserAdminSession().findUser(admin, username);
        final int status;
        if (data == null) {
        	throw new Exception("User we have added can not be found");
        }
        status = data.getStatus();
        log.debug("status: " + status);
        result = status == UserDataConstants.STATUS_GENERATED;
        return result;
    }
    
    /**
     * @return The host's names or null if it could not be determined.
     */
    private Set<String> getHostNames() throws Exception {
    	final Set<String> hostnames = new HashSet<String>();
    	
    	// Normally this is the hostname
    	final String hostname = InetAddress.getLocalHost().getHostName();
    	if (hostnames != null) {
    		hostnames.add(hostname);
    	}
    	
    	// Maybe we have a fully qualified hostname
    	final String fullHostname = InetAddress.getLocalHost().getCanonicalHostName();
    	if (fullHostname != null) {
    		hostnames.add(fullHostname);
    	}
    	
	    return hostnames;
    }
    
    private UserAdminSession getUserAdminSession() {
		return userAdminSession;
	}
    
    public ServiceSession getServiceSession() {
		return serviceSession;
	}
}
