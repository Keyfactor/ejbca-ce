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

package se.anatom.ejbca.ra.userdatasource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.util.CertTools;


/**
 * Tests User Data Sources.
 *
 * @version $Id: TestUserDataSource.java,v 1.1 2006-07-20 17:50:18 herrvendil Exp $
 */
public class TestUserDataSource extends TestCase {
        
    private static Logger log = Logger.getLogger(TestUserDataSource.class);
    private static Context ctx;
    private static IUserDataSourceSessionRemote pub;
    
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    
    /**
     * Creates a new TestUserDataSource object.
     *
     * @param name name
     */
    public TestUserDataSource(String name) {
        super(name);
    }
    
    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();
        
        Object obj = ctx.lookup("UserDataSourceSession");
        IUserDataSourceSessionHome home = (IUserDataSourceSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
                IUserDataSourceSessionHome.class);
        pub = home.create();
        
        CertTools.installBCProvider();
        
        log.debug("<setUp()");
        
    }
    
    protected void tearDown() throws Exception {
    }
    
    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");
        
        return ctx;
    }
    
    
    /**
     * adds custom userdatasource
     *
     * @throws Exception error
     */
    public void test01AddCustomUserDataSource() throws Exception {
        log.debug(">test01AddCustomUserDataSource()");
        boolean ret = false;
        try {
            CustomUserDataSourceContainer userdatasource = new CustomUserDataSourceContainer();
            userdatasource.setClassPath("org.ejbca.core.model.ra.userdatasource.DummyCustomUserDataSource");
            userdatasource.setDescription("Used in Junit Test, Remove this one");
            pub.addUserDataSource(admin, "TESTDUMMYCUSTOM", userdatasource);
            ret = true;
        } catch (UserDataSourceExistsException pee) {
        }
        
        assertTrue("Creating Custom UserDataSource failed", ret);
        
        log.debug("<test01AddCustomUserDataSource()");
    }
    
    /**
     * renames userdatasource
     *
     * @throws Exception error
     */
    public void test02RenameUserDataSource() throws Exception {
        log.debug(">test02RenameUserDataSource()");
        
        boolean ret = false;
        try {
            pub.renameUserDataSource(admin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");
            ret = true;
        } catch (UserDataSourceExistsException pee) {
        }
        assertTrue("Renaming Custom UserDataSource failed", ret);
        
        
        log.debug("<test02RenameUserDataSource()");
    }
    
    /**
     * clones userdatasource
     *
     * @throws Exception error
     */
    public void test03CloneUserDataSource() throws Exception {
        log.debug(">test03CloneUserDataSource()");
        
        boolean ret = false;
        pub.cloneUserDataSource(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
        ret = true;
        assertTrue("Cloning Custom UserDataSource failed", ret);
        
        log.debug("<test03CloneUserDataSource()");
    }
    
    
    /**
     * edits userdatasource
     *
     * @throws Exception error
     */
    public void test04EditUserDataSource() throws Exception {
        log.debug(">test04EditUserDataSource()");
        
        boolean ret = false;
        
        BaseUserDataSource userdatasource = pub.getUserDataSource(admin, "TESTCLONEDUMMYCUSTOM");
        userdatasource.setDescription(userdatasource.getDescription().toUpperCase());
        pub.changeUserDataSource(admin, "TESTCLONEDUMMYCUSTOM", userdatasource);
        ret = true;
        
        assertTrue("Editing Custom UserDataSource failed", ret);
        
        
        log.debug("<test04EditUserDataSource()");
    }
    
    /**
     * Tries to retrieve userdata from dummy user data source
     *
     * @throws Exception error
     */
    public void test05FetchFromDummy() throws Exception {
        log.debug(">test05FetchFromDummy()");
        
        ArrayList userdatasources = new ArrayList();
        userdatasources.add(new Integer(pub.getUserDataSourceId(admin, "TESTNEWDUMMYCUSTOM")));
        
        Collection ret = pub.fetch(admin,userdatasources,"per");
        assertTrue("Fetching data from dummy userdatasource failed", ret.size() ==1);
        
        Iterator iter = ret.iterator();
        UserDataSourceVO next = (UserDataSourceVO) iter.next();
        assertTrue("Didn't get epected user data", next.getUserDataVO().getUsername().equals("PER"));        

        log.debug("<test05FetchFromDummy()");
    }
    
    
    /**
     * removes all userdatasources
     *
     * @throws Exception error
     */
    public void test06removeUserDataSources() throws Exception {
        log.debug(">test06removeUserDataSources()");
        boolean ret = false;
        try {
            pub.removeUserDataSource(admin, "TESTNEWDUMMYCUSTOM");
            pub.removeUserDataSource(admin, "TESTCLONEDUMMYCUSTOM");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing UserDataSource failed", ret);
        
        log.debug("<test06removeUserDataSources()");
    }
}
