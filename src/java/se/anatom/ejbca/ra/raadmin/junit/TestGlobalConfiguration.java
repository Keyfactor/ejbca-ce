package se.anatom.ejbca.ra.raadmin.junit;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

/**
 * Tests the global configuration entity bean.
 *
 * @version $Id: TestGlobalConfiguration.java,v 1.1 2004-03-14 13:56:27 herrvendil Exp $
 */
public class TestGlobalConfiguration extends TestCase {
	private static Logger log = Logger.getLogger(TestGlobalConfiguration.class);
    
    private IRaAdminSessionRemote cacheAdmin;

    private static IRaAdminSessionHome cacheHome;


    /**
     * Creates a new TestGlobalConfiguration object.
     *
     * @param name name
     */
    public TestGlobalConfiguration(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if( cacheAdmin == null ) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("RaAdminSession");
                cacheHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);                
                
            }

            cacheAdmin = cacheHome.create();
        }

                 
        
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
     * tests adding a global configuration
     *
     * @throws Exception error
     */
    public void test01AddGlobalConfiguration() throws Exception {
        log.debug(">test01AddGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        GlobalConfiguration conf = new GlobalConfiguration();
        conf.setEjbcaTitle("TESTTITLE");       
        this.cacheAdmin.saveGlobalConfiguration(administrator,conf); 
        
        log.debug("<test01AddGlobalConfiguration()");
    }
    
    /**
     * tests modifying an global configuration
     *
     * @throws Exception error
     */
    public void test02ModifyGlobalConfiguration() throws Exception {
        log.debug(">test01ModifyGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        GlobalConfiguration conf = this.cacheAdmin.loadGlobalConfiguration(administrator);
        assertTrue( "Error Retreiving Global Configuration.", conf.getEjbcaTitle().equals("TESTTITLE"));                                

        conf.setEjbcaTitle("TESTTITLE2");       
        this.cacheAdmin.saveGlobalConfiguration(administrator,conf); 
                      
        
        log.debug("<test01ModifyGlobalConfiguration()");
    }
    
    
}
