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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.InterfaceCache;

/**
 * Tests authentication session used by signer.
 *
 * @version $Id$
 */
public class AuthorizationSessionTest extends TestCase {
    
    public static final String DEFAULT_SUPERADMIN_CN = "SuperAdmin";
    
    private static final Logger log = Logger.getLogger(AuthorizationSessionTest.class);

    private static int caid="CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();
    private final static Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();
    
    /**
     * Creates a new TestAuthenticationSession object.
     *
     * @param name name
     */
    public AuthorizationSessionTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * tests initialization of authorization bean
     *
     * @throws Exception error
     */
    public void test01Initialize() throws Exception {
        log.trace(">test01Initialize()");
        
        // Initialize with a new CA
        authorizationSession.initialize(admin, caid, DEFAULT_SUPERADMIN_CN);

        // Retrieve access rules and check that they were added
        AdminGroup ag = authorizationSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        Collection<AccessRule> rules = ag.getAccessRules();
        assertEquals("Number of available access rules for AdminGroup.PUBLICWEBGROUPNAME was not the expected.", 8, rules.size());

        // Add some new strange access rules
		ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
		accessrules.add(new AccessRule("/public_foo_user", AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule("/foo_functionality/basic_functions", AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule("/foo_functionality/view_certificate", AccessRule.RULE_ACCEPT, false));
        authorizationSession.addAccessRules(admin, AdminGroup.PUBLICWEBGROUPNAME, accessrules);
        
        // Retrieve the access rules and check that they were added
        ag = authorizationSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(11, rules.size()); // We have added three rules
        Iterator<AccessRule> iter = rules.iterator();
        boolean found = false;
        while (iter.hasNext()) {
        	AccessRule rule = iter.next();
        	if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
        		found = true;
        	}
        }
        assertTrue(found);
        
        // Initialize the same CA again, this will remove old default Public Web rules and create new ones.
        // This had some troubles with glassfish before, hence the creation of this test
        authorizationSession.initialize(admin, caid, DEFAULT_SUPERADMIN_CN);
        // Retrieve access rules and check that we only have the default ones
        ag = authorizationSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
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
        
        log.trace("<test01Initialize()");
    }

    public void test02ExistMethods() throws Exception {
    	log.trace(">test02ExistMethods");
    	authorizationSession.existsCAInRules(admin, caid);
    	log.trace("<test02ExistMethods");
    }
    
}
