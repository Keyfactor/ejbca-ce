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

package org.ejbca.core.ejb.ra.userdatasource;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests User Data Sources.
 *
 * @version $Id$
 */
public class UserDataSourceTest {
        
    private static final Logger log = Logger.getLogger(UserDataSourceTest.class);
    private static AuthenticationToken admin;
    
    private SimpleAuthenticationProviderRemote simpleAuthenticationProvider = JndiHelper.getRemoteSession(SimpleAuthenticationProviderRemote.class);
    private UserDataSourceSessionRemote userDataSourceSession = InterfaceCache.getUserDataSourceSession();

    @Before
    public void setUp() throws Exception {
        admin = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(null, null));
    }
    
    @After
    public void tearDown() throws Exception {
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
        assertTrue("Didn't get epected user data", next.getUserDataVO().getUsername().equals("PER"));
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
}
