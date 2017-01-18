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

package org.ejbca.core.ejb.ra.userdatasource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests User Data Sources.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UserDataSourceTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(UserDataSourceTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserDataSourceTest"));
    private static TestX509CertificateAuthenticationToken admin;

    private static final String ROLENAME = "USERDATASOURCE_EDITOR";

    private RoleManagementSessionRemote roleManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private UserDataSourceSessionRemote userDataSourceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class);

    @Override
    public String getRoleName() {
        return ROLENAME;
    }

    @Before
    public void setUp() throws Exception {
        admin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(null, null));
        AdminGroupData role = roleManagementSessionRemote.create(internalAdmin, ROLENAME);
        Collection<AccessUserAspectData> subjects = new LinkedList<AccessUserAspectData>();
        subjects.add(new AccessUserAspectData(ROLENAME, CertTools.getIssuerDN(admin.getCertificate()).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, CertTools.getPartFromDN(SimpleAuthenticationProviderSessionRemote.DEFAULT_DN, "CN")));
        role = roleManagementSessionRemote.addSubjectsToRole(internalAdmin, role, subjects);
        Collection<AccessRuleData> accessRules = new LinkedList<AccessRuleData>();
        accessRules.add(new AccessRuleData(ROLENAME, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES, AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(ROLENAME, AccessRulesConstants.USERDATASOURCEPREFIX + Integer.valueOf(userDataSourceSession.getUserDataSourceId(admin, "TESTNEWDUMMYCUSTOM")) + AccessRulesConstants.UDS_FETCH_RIGHTS, AccessRuleState.RULE_ACCEPT, false));
        role = roleManagementSessionRemote.addAccessRulesToRole(internalAdmin, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        roleManagementSessionRemote.remove(internalAdmin, ROLENAME);
    }

    @Test
    public void test01AddCustomUserDataSource() throws Exception {
        log.trace(">test01AddCustomUserDataSource()");
        boolean ret = false;
        try {
            CustomUserDataSourceContainer userdatasource = new CustomUserDataSourceContainer();
            userdatasource.setClassPath("org.ejbca.core.model.ra.userdatasource.DummyCustomUserDataSource");
            userdatasource.setDescription("Used in Junit Test, Remove this one");
            userDataSourceSession.addUserDataSource(admin, "TESTDUMMYCUSTOM", userdatasource);
            ret = true;
        } catch (UserDataSourceExistsException pee) {
        }

        assertTrue("Creating Custom UserDataSource failed", ret);
        log.trace("<test01AddCustomUserDataSource()");
    }

    @Test
    public void test02RenameUserDataSource() throws Exception {
        log.trace(">test02RenameUserDataSource()");
        boolean ret = false;
        try {
            userDataSourceSession.renameUserDataSource(admin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");
            ret = true;
        } catch (UserDataSourceExistsException pee) {
        }
        assertTrue("Renaming Custom UserDataSource failed", ret);
        log.trace("<test02RenameUserDataSource()");
    }

    @Test
    public void test03CloneUserDataSource() throws Exception {
        log.trace(">test03CloneUserDataSource()");
        boolean ret = false;
        userDataSourceSession.cloneUserDataSource(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
        ret = true;
        assertTrue("Cloning Custom UserDataSource failed", ret);
        log.trace("<test03CloneUserDataSource()");
    }

    @Test
    public void test04EditUserDataSource() throws Exception {
        log.trace(">test04EditUserDataSource()");
        boolean ret = false;

        BaseUserDataSource userdatasource = userDataSourceSession.getUserDataSource(admin, "TESTCLONEDUMMYCUSTOM");
        userdatasource.setDescription(userdatasource.getDescription().toUpperCase());
        userDataSourceSession.changeUserDataSource(admin, "TESTCLONEDUMMYCUSTOM", userdatasource);
        ret = true;

        assertTrue("Editing Custom UserDataSource failed", ret);
        log.trace("<test04EditUserDataSource()");
    }

    @Test
    public void test05FetchFromDummy() throws Exception {
        log.trace(">test05FetchFromDummy()");
        ArrayList<Integer> userdatasources = new ArrayList<Integer>();
        userdatasources.add(Integer.valueOf(userDataSourceSession.getUserDataSourceId(admin, "TESTNEWDUMMYCUSTOM")));

        Collection<UserDataSourceVO> ret = userDataSourceSession.fetch(admin, userdatasources, "per");
        assertTrue("Fetching data from dummy userdatasource failed", ret.size() == 1);

        Iterator<UserDataSourceVO> iter = ret.iterator();
        UserDataSourceVO next = iter.next();
        assertTrue("Didn't get epected user data", next.getEndEntityInformation().getUsername().equals("PER"));
        log.trace("<test05FetchFromDummy()");
    }

    @Test
    public void test06removeUserDataSources() throws Exception {
        log.trace(">test06removeUserDataSources()");
        boolean ret = false;
        try {
            userDataSourceSession.removeUserDataSource(admin, "TESTNEWDUMMYCUSTOM");
            userDataSourceSession.removeUserDataSource(admin, "TESTCLONEDUMMYCUSTOM");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing UserDataSource failed", ret);
        log.trace("<test06removeUserDataSources()");
    }

    @Test
    public void testIsAuthorizedToUserDataSource() throws Exception {
        final String rolename = "testIsAuthorizedToUserDataSource";
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("CN="+rolename));
        TestX509CertificateAuthenticationToken adminNoAuth = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
                .authenticate(new AuthenticationSubject(principals, null));

        final int caid = CertTools.getIssuerDN(admin.getCertificate()).hashCode();
        final String cN = CertTools.getPartFromDN(CertTools.getIssuerDN(admin.getCertificate()), "CN");
        AdminGroupData role = roleManagementSessionRemote.create(internalAdmin, rolename);
        final String alias = "spacemonkeys";
        try {
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(new AccessUserAspectData(rolename, caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, cN));
            role = roleManagementSessionRemote.addSubjectsToRole(internalAdmin, role, subjects);
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            // Not authorized to user data sources
            accessRules.add(new AccessRuleData(rolename, AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, true));
            role = roleManagementSessionRemote.addAccessRulesToRole(internalAdmin, role, accessRules);

            CustomUserDataSourceContainer userdatasource = new CustomUserDataSourceContainer();
            userdatasource.setClassPath("org.ejbca.core.model.ra.userdatasource.DummyCustomUserDataSource");
            userdatasource.setDescription("Used in Junit Test, Remove this one");

            // Test authorization to edit with an unauthorized admin
            try {
                userDataSourceSession.addUserDataSource(adminNoAuth, alias, userdatasource);
                fail("admin should not have been authorized to edit user data source");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Error, not authorized to user data source spacemonkeys.", e.getMessage());
            }
            try {
                userDataSourceSession.changeUserDataSource(adminNoAuth, alias, userdatasource);
                fail("admin should not have been authorized to edit user data source");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Error, not authorized to user data source spacemonkeys.", e.getMessage());
            }
            // Add so we can try to clone, remove and rename
            userDataSourceSession.addUserDataSource(internalAdmin, alias, userdatasource);
            try {
                userDataSourceSession.cloneUserDataSource(adminNoAuth, alias, "newmonkeys");
                fail("admin should not have been authorized to edit user data source");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Error, not authorized to user data source newmonkeys.", e.getMessage());
            }
            try {
                userDataSourceSession.removeUserDataSource(adminNoAuth, alias);
                fail("admin should not have been authorized to edit user data source");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Error, not authorized to user data source spacemonkeys.", e.getMessage());
            }
            try {
                userDataSourceSession.renameUserDataSource(adminNoAuth, alias, "renamedmonkey");
                fail("admin should not have been authorized to edit user data source");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Error, not authorized to user data source spacemonkeys.", e.getMessage());
            }

        } finally {
            userDataSourceSession.removeUserDataSource(internalAdmin, alias);
            roleManagementSessionRemote.remove(internalAdmin, rolename);
        }
    }

}
