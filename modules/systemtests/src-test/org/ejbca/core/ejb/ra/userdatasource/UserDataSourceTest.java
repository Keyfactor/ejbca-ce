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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
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
public class UserDataSourceTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(UserDataSourceTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("UserDataSourceTest");

    private static final String ROLENAME = "USERDATASOURCE_EDITOR";
    private static final String USERDATASOURCE1_NAME = "TESTDUMMYCUSTOM";
    private static final String USERDATASOURCE2_NAME = "TESTNEWDUMMYCUSTOM";
    private static final String USERDATASOURCE3_NAME = "TESTCLONEDUMMYCUSTOM";

    private RoleInitializationSessionRemote roleInitializationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private UserDataSourceSessionRemote userDataSourceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class);

    private TestX509CertificateAuthenticationToken admin;

    @Before
    public void setUp() throws Exception {
        final int userDataSourceId = userDataSourceSession.getUserDataSourceId(admin, USERDATASOURCE2_NAME);
        super.setUpAuthTokenAndRole(null, ROLENAME, Arrays.asList(
                AccessRulesConstants.ROLE_ADMINISTRATOR,
                AccessRulesConstants.REGULAR_EDITUSERDATASOURCES,
                AccessRulesConstants.USERDATASOURCEPREFIX + userDataSourceId + AccessRulesConstants.UDS_FETCH_RIGHTS
                ), null);
        admin = roleMgmgToken;
    }

    @After
    public void tearDown() throws Exception {
        super.tearDownRemoveRole();
    }

    @Test
    public void test01AddCustomUserDataSource() throws Exception {
        log.trace(">test01AddCustomUserDataSource()");
        boolean ret = false;
        try {
            CustomUserDataSourceContainer userdatasource = new CustomUserDataSourceContainer();
            userdatasource.setClassPath("org.ejbca.core.model.ra.userdatasource.DummyCustomUserDataSource");
            userdatasource.setDescription("Used in Junit Test, Remove this one");
            userDataSourceSession.addUserDataSource(admin, USERDATASOURCE1_NAME, userdatasource);
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
            userDataSourceSession.renameUserDataSource(admin, USERDATASOURCE1_NAME, USERDATASOURCE2_NAME);
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
        userDataSourceSession.cloneUserDataSource(admin, USERDATASOURCE2_NAME, USERDATASOURCE3_NAME);
        ret = true;
        assertTrue("Cloning Custom UserDataSource failed", ret);
        log.trace("<test03CloneUserDataSource()");
    }

    @Test
    public void test04EditUserDataSource() throws Exception {
        log.trace(">test04EditUserDataSource()");
        boolean ret = false;
        BaseUserDataSource userdatasource = userDataSourceSession.getUserDataSource(admin, USERDATASOURCE3_NAME);
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
        userdatasources.add(Integer.valueOf(userDataSourceSession.getUserDataSourceId(admin, USERDATASOURCE2_NAME)));
        Collection<UserDataSourceVO> ret = userDataSourceSession.fetch(admin, userdatasources, "per");
        assertTrue("Fetching data from dummy userdatasource failed", ret.size() == 1);
        UserDataSourceVO next = ret.iterator().next();
        assertTrue("Didn't get epected user data", next.getEndEntityInformation().getUsername().equals("PER"));
        log.trace("<test05FetchFromDummy()");
    }

    @Test
    public void test06removeUserDataSources() throws Exception {
        log.trace(">test06removeUserDataSources()");
        boolean ret = false;
        try {
            userDataSourceSession.removeUserDataSource(admin, USERDATASOURCE2_NAME);
            userDataSourceSession.removeUserDataSource(admin, USERDATASOURCE3_NAME);
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing UserDataSource failed", ret);
        log.trace("<test06removeUserDataSources()");
    }

    @Test
    public void testIsAuthorizedToUserDataSource() throws Exception {
        final String rolename = "testIsAuthorizedToUserDataSource";
        final TestX509CertificateAuthenticationToken adminNoAuth = roleInitializationSessionRemote.createAuthenticationTokenAndAssignToNewRole(
                "CN="+rolename, null, rolename, Arrays.asList(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES), null);
        final String alias = "spacemonkeys";
        try {
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
            roleInitializationSessionRemote.removeAllAuthenticationTokensRoles(adminNoAuth);
        }
    }
}
