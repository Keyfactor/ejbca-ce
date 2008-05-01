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

package org.ejbca.core.ejb.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;


/**
 * Tests authentication session used by signer.
 *
 * @version $Id$
 */
public class TestAuthorizationSession extends TestCase {
    private static Logger log = Logger.getLogger(TestAuthorizationSession.class);

    private static Context ctx;
    private static IAuthorizationSessionRemote authorizationsession;
    private static int caid="CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();
    private static Admin admin = null;

    /**
     * Creates a new TestAuthenticationSession object.
     *
     * @param name name
     */
    public TestAuthorizationSession(String name) {
        super(name);

        try {
            ctx = getInitialContext();
            Object obj = ctx.lookup(IAuthorizationSessionHome.JNDI_NAME);
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IAuthorizationSessionHome.class);                
            authorizationsession = authorizationsessionhome.create(); 
            
            admin = new Admin(Admin.TYPE_INTERNALUSER);
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue("Exception on setup", false);
        } 
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        Context ctx = new javax.naming.InitialContext();
        return ctx;
    }


    /**
     * tests initialization of authorization bean
     *
     * @throws Exception error
     */
    public void test01Initialize() throws Exception {
        log.debug(">test01Initialize()");
        
        // Initialize with a new CA
        authorizationsession.initialize(admin, caid);

        // Retrieve access rules and check that they were added
        AdminGroup ag = authorizationsession.getAdminGroup(admin, LocalAuthorizationSessionBean.PUBLICWEBGROUPNAME, caid);
        assertNotNull(ag);
        Collection rules = ag.getAccessRules();
        assertEquals(8, rules.size());

        // Add some new strange access rules
		ArrayList accessrules = new ArrayList();
		accessrules.add(new AccessRule("/public_foo_user", AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule("/foo_functionality/basic_functions", AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule("/foo_functionality/view_certificate", AccessRule.RULE_ACCEPT, false));
        authorizationsession.addAccessRules(admin, LocalAuthorizationSessionBean.PUBLICWEBGROUPNAME, caid, accessrules);
        
        // Retrieve the access rules and check that they were added
        ag = authorizationsession.getAdminGroup(admin, LocalAuthorizationSessionBean.PUBLICWEBGROUPNAME, caid);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(11, rules.size()); // We have added three rules
        Iterator iter = rules.iterator();
        boolean found = false;
        while (iter.hasNext()) {
        	AccessRule rule = (AccessRule)iter.next();
        	if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
        		found = true;
        	}
        }
        assertTrue(found);
        
        // Initialize the same CA again, this will remove old default Public Web rules and create new ones.
        // This had some troubles with glassfish before, hence the creation of this test
        authorizationsession.initialize(admin, caid);
        // Retrieve access rules and check that we only have the default ones
        ag = authorizationsession.getAdminGroup(admin, LocalAuthorizationSessionBean.PUBLICWEBGROUPNAME, caid);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(8, rules.size());
        iter = rules.iterator();
        found = false;
        while (iter.hasNext()) {
        	AccessRule rule = (AccessRule)iter.next();
        	if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
        		found = true;
        	}
        }
        assertFalse(found);
        
        log.debug("<test01Initialize()");
    }

    public void test02ExistMethods() throws Exception {
    	log.debug(">test02ExistMethods");
    	authorizationsession.existsCAInRules(admin, caid);
    	log.debug("<test02ExistMethods");
    }
    
}
