package se.anatom.ejbca.ra.raadmin.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.ra.raadmin.*;
import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests the GlobalConfiguration entity bean and some parts of RaAdminSession.
 *
 * @version $Id: TestGlobalConfigurationData.java,v 1.2 2002-06-13 13:52:57 anatom Exp $
 */

public class TestGlobalConfigurationData extends TestCase {

    static Category cat = Category.getInstance( TestGlobalConfigurationData.class.getName() );
    private static Context ctx;
    private static IRaAdminSessionHome home;
    private static String title;
    private static String title2;

    public TestGlobalConfigurationData(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("RaAdminSession");
        home = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IRaAdminSessionHome.class);
        cat.debug("<setUp()");

    }
    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        cat.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        cat.debug("<getInitialContext");
        return ctx;
    }

    public void test01CreateGlobalConfiguration() throws Exception {
        cat.debug(">test01CreateGlobalConfiguration()");
        title= "CREATED!";
        title2= "CHANGED!";
        GlobalConfiguration globalconfiguration = new GlobalConfiguration();
        globalconfiguration.setEjbcaTitle(title);
        IRaAdminSessionRemote raadminsession = home.create();
        raadminsession.saveGlobalConfiguration(globalconfiguration);
        cat.debug("created it!");
        cat.debug("<test01CreateGlobalConfiguration()");
    }

    public void test02LookupAndChangeTitle() throws Exception {
        cat.debug(">test02LookupAndChangeUser()");
        GlobalConfiguration gc;
        IRaAdminSessionRemote raadminsession = home.create();
        gc = raadminsession.loadGlobalConfiguration();
        cat.debug("Title="+gc.getEjbcaTitle());
        assertTrue( "wrong title", gc.getEjbcaTitle().equals(title) );
        gc.setEjbcaTitle(title2);
        cat.debug("New title="+gc.getEjbcaTitle());
        raadminsession.saveGlobalConfiguration(gc);
        cat.debug("Changed it");
        cat.debug("<test02LookupAndChangeUser()");
    }

    public void test03LookupChangedTitle() throws Exception {
        cat.debug(">test03LookupChangedUser()");
        GlobalConfiguration gc;
        IRaAdminSessionRemote raadminsession = home.create();
        gc = raadminsession.loadGlobalConfiguration();
        assertNotNull(gc);
        cat.debug("loaded global configuration! =");
        cat.debug("title="+gc.getEjbcaTitle());
        assertTrue( "wrong title", gc.getEjbcaTitle().equals(title2) );
        cat.debug("<test03LookupChangedTitle()");
    }
}

