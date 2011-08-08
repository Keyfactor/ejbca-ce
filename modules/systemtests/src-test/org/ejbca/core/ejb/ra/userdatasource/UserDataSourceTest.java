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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.util.InterfaceCache;

/**
 * Tests User Data Sources.
 *
 * @version $Id$
 */
public class UserDataSourceTest extends TestCase {
        
    private static final Logger log = Logger.getLogger(UserDataSourceTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    
    private UserDataSourceSessionRemote userDataSourceSession = InterfaceCache.getUserDataSourceSession();
    
    /**
     * Creates a new TestUserDataSource object.
     *
     * @param name name
     */
    public UserDataSourceTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
    }
    
    public void setUp() throws Exception {
    }
    
    public void tearDown() throws Exception {
    }
    
    /**
     * adds custom userdatasource
     *
     * @throws Exception error
     */
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

    /**
     * renames userdatasource
     * 
     * @throws Exception
     *             error
     */
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

    /**
     * clones userdatasource
     * 
     * @throws Exception
     *             error
     */
    public void test03CloneUserDataSource() throws Exception {
        log.trace(">test03CloneUserDataSource()");
        boolean ret = false;
        userDataSourceSession.cloneUserDataSource(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
        ret = true;
        assertTrue("Cloning Custom UserDataSource failed", ret);
        log.trace("<test03CloneUserDataSource()");
    }

    /**
     * edits userdatasource
     * 
     * @throws Exception
     *             error
     */
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

    /**
     * Tries to retrieve userdata from dummy user data source
     * 
     * @throws Exception
     *             error
     */
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

    /**
     * removes all userdatasources
     * 
     * @throws Exception
     *             error
     */
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
