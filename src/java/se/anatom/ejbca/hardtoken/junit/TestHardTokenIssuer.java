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
 
package se.anatom.ejbca.hardtoken.junit;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.hardtoken.HardTokenIssuer;
import se.anatom.ejbca.hardtoken.HardTokenIssuerData;
import se.anatom.ejbca.hardtoken.IHardTokenSessionHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionRemote;
import se.anatom.ejbca.log.Admin;

/**
 * Tests the Hard Token Issuer entity bean.
 *
 * @version $Id: TestHardTokenIssuer.java,v 1.2 2004-04-16 07:39:01 anatom Exp $
 */
public class TestHardTokenIssuer extends TestCase {
	private static Logger log = Logger.getLogger(TestHardTokenIssuer.class);
    private IHardTokenSessionRemote cacheAdmin;


    private static IHardTokenSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestHardTokenIssuer object.
     *
     * @param name name
     */
    public TestHardTokenIssuer(String name) {
        super(name);
    }

    protected void setUp() throws Exception  {

        log.debug(">setUp()");

        if( cacheAdmin == null ) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("HardTokenSession");
                cacheHome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IHardTokenSessionHome.class);                
                
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
     * adds a issuer to the database
     *
     * @throws Exception error
     */
    public void test01AddHardTokenIssuer() throws Exception {
        log.debug(">test01AddHardTokenIssuer()");
        boolean ret = false;
        HardTokenIssuer issuer = new HardTokenIssuer();
        issuer.setDescription("TEST");
                             
        ret = cacheAdmin.addHardTokenIssuer(admin, "TEST", 3 ,issuer);
                  
                 
        assertTrue("Creating Hard Token Issuer failed", ret); 
        log.debug("<test01AddHardTokenIssuer()");
    }

    /**
     * renames issuer
     *
     * @throws Exception error
     */
    public void test02RenameHardTokenIssuer() throws Exception {
        log.debug(">test02RenameHardTokenIssuer()");

        boolean ret = false;
        ret = cacheAdmin.renameHardTokenIssuer(admin, "TEST", "TEST2", 4);                 
        assertTrue("Renaming Hard Token Issuer failed", ret);
                
        log.debug("<test02RenameHardTokenIssuer()");
    }

    /**
     * clones issuer
     *
     * @throws Exception error
     */
    public void test03CloneHardTokenIssuer() throws Exception {
        log.debug(">test03CloneHardTokenIssuer()");

        boolean ret = false;
        ret = cacheAdmin.cloneHardTokenIssuer(admin, "TEST2", "TEST", 4);          
                           
        assertTrue("Cloning Certificate Profile failed", ret);        
        
        log.debug("<test03CloneHardTokenIssuer()");
    }
    
    
    
    /**
     * edits issuer
     *
     * @throws Exception error
     */	
    public void test04EditHardTokenIssuer() throws Exception {
    	log.debug(">test04EditHardTokenIssuer()");

        boolean ret = false;
        
        HardTokenIssuerData issuerdata = cacheAdmin.getHardTokenIssuerData(admin, "TEST");
        assertTrue("Retrieving HardTokenIssuer failed", issuerdata.getHardTokenIssuer().getDescription().equals("TEST"));
        
        issuerdata.getHardTokenIssuer().setDescription("TEST2");
        
        ret = cacheAdmin.changeHardTokenIssuer(admin, "TEST", issuerdata.getHardTokenIssuer());                            
                         
        assertTrue("Editing HardTokenIssuer failed", ret);        

    	    	
    	log.debug("<test04EditHardTokenIssuer()");
    }
    
         
    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeHardTokenIssuers() throws Exception {
        log.debug(">test05removeHardTokenIssuers()");        
        boolean ret = false;
        try{
          cacheAdmin.removeHardTokenIssuer(admin,"TEST");
          cacheAdmin.removeHardTokenIssuer(admin,"TEST2");
          ret = true;
        }catch(Exception pee){}                 
        assertTrue("Removing Certificate Profile failed", ret);
        
        log.debug("<test05removeHardTokenIssuers()");
    }
    
    
}
