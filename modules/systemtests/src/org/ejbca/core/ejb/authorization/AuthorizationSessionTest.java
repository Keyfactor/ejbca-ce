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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;

/**
 * Tests authentication session used by signer.
 * 
 * @version $Id: AuthorizationSessionTest.java 9566 2010-07-29 23:12:16Z jeklund
 *          $
 */
public class AuthorizationSessionTest extends CaTestCase {

    public static final String DEFAULT_SUPERADMIN_CN = "SuperAdmin";

    //private static final Logger log = Logger.getLogger(AuthorizationSessionTest.class);

    private Admin admin;

    private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    /**
     * Creates a new TestAuthenticationSession object.
     * 
     * @param name
     *            name
     */
    public AuthorizationSessionTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        super.setUp();
        createTestCA();
    }

    public void tearDown() throws Exception {
        super.tearDown();
        removeTestCA();
    }

    /**
     * tests initialization of authorization bean
     * 
     * @throws Exception
     *             error
     */
    public void testInitialize() throws Exception {

        admin = new Admin(Admin.TYPE_INTERNALUSER);
        int caid = "CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();

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

        // Initialize the same CA again, this will remove old default Public Web
        // rules and create new ones.
        // This had some troubles with glassfish before, hence the creation of
        // this test
        authorizationSession.initialize(admin, caid, DEFAULT_SUPERADMIN_CN);
        // Retrieve access rules and check that we only have the default ones
        ag = authorizationSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(8, rules.size());
        iter = rules.iterator();
        found = false;
        while (iter.hasNext()) {
            AccessRule rule = (AccessRule) iter.next();
            if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
                found = true;
            }
        }
        assertFalse(found);

    }

    public void testExistMethods() throws Exception {
        int caid = "CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();
        authorizationSession.existsCAInRules(admin, caid);

    }

    public void testIsAuthorizedInternalUserRegularApproveIdentity() {
        admin = new Admin(Admin.TYPE_INTERNALUSER);
        try {
            authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        } catch (AuthorizationDeniedException e) {
            fail("Could not authorize internal user with AccessRulesConstants.REGULAR_APPROVEENDENTITY");
        }
    }

    public void testIsAuthorizedCertUserRegularApproveIdentity() throws Exception {
        
        String adminusername = genRandomUserName();
        Admin intadmin = new Admin(Admin.TYPE_INTERNALUSER);

        int caid = getTestCAId();
        
        UserDataVO userdata = new UserDataVO(adminusername, "CN=" + adminusername, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");

        userAdminSession.addUser(intadmin, userdata, true);
        
        File tmpfile = File.createTempFile("ejbca", "p12");
        BatchMakeP12 makep12 = new BatchMakeP12();
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        tmpfile.delete();
        
        List<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
        adminEntities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, adminusername, caid));
        authorizationSession.addAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminEntities);
        authorizationSession.forceRuleUpdate(intadmin);
        
        X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(intadmin, adminusername).iterator().next();
        admin = new Admin(admincert, adminusername, null);

        try {
            authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        } catch (AuthorizationDeniedException e) {
            fail("Could not authorize certificate user with AccessRulesConstants.REGULAR_APPROVEENDENTITY");
        }
    }

}
