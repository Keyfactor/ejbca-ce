package se.anatom.ejbca.ra.raadmin.junit;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

/**
 * Tests the end entity profile entity bean.
 *
 * @version $Id: TestEndEntityProfile.java,v 1.1 2004-03-14 13:56:18 herrvendil Exp $
 */
public class TestEndEntityProfile extends TestCase {
	private static Logger log = Logger.getLogger(TestEndEntityProfile.class);
    private IRaAdminSessionRemote cacheAdmin;


    private static IRaAdminSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestEndEntityProfile object.
     *
     * @param name name
     */
    public TestEndEntityProfile(String name) {
        super(name);
    }

    protected void setUp() throws Exception  {

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
     * adds a publishers to the database
     *
     * @throws Exception error
     */
    public void test01AddEndEntityProfile() throws Exception {
        log.debug(">test01AddEndEntityProfile()");
        boolean ret = false;
        try{
          EndEntityProfile profile = new EndEntityProfile();
          profile.addField(EndEntityProfile.ORGANIZATIONUNIT);
                    
          cacheAdmin.addEndEntityProfile(admin, "TEST",profile);
          
          ret = true;
        }catch(EndEntityProfileExistsException pee){}
                 
        assertTrue("Creating End Entity Profile failed", ret); 
        log.debug("<test01AddEndEntityProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameEndEntityProfile() throws Exception {
        log.debug(">test02RenameEndEntityProfile()");

        boolean ret = false;
        try{                      
          cacheAdmin.renameEndEntityProfile(admin, "TEST", "TEST2");          
          ret = true;
        }catch(EndEntityProfileExistsException pee){}                 
        assertTrue("Renaming End Entity Profile failed", ret);
                
        log.debug("<test02RenameEndEntityProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneEndEntityProfile() throws Exception {
        log.debug(">test03CloneEndEntityProfile()");

        boolean ret = false;
        try{                      
          cacheAdmin.cloneEndEntityProfile(admin, "TEST2", "TEST");          
          ret = true;
        }catch(EndEntityProfileExistsException pee){}                 
        assertTrue("Cloning End Entity Profile failed", ret);        
        
        log.debug("<test03CloneEndEntityProfile()");
    }
    
    
    
    /**
     * edits profile
     *
     * @throws Exception error
     */	
    public void test04EditEndEntityProfile() throws Exception {
    	log.debug(">test04EditEndEntityProfile()");

        boolean ret = false;
        
        EndEntityProfile profile = cacheAdmin.getEndEntityProfile(admin, "TEST");
        assertTrue("Retrieving EndEntityProfile failed", profile.getNumberOfField(EndEntityProfile.ORGANIZATIONUNIT) == 1);
        
        profile.addField(EndEntityProfile.ORGANIZATIONUNIT);
        
        cacheAdmin.changeEndEntityProfile(admin, "TEST", profile);                    
        ret = true;
                         
        assertTrue("Editing EndEntityProfile failed", ret);        

    	
    	
    	log.debug("<test04EditEndEntityProfile()");
    }
    
         
    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeEndEntityProfiles() throws Exception {
        log.debug(">test05removeEndEntityProfiles()");        
        boolean ret = false;
        try{
          cacheAdmin.removeEndEntityProfile(admin,"TEST");
          cacheAdmin.removeEndEntityProfile(admin,"TEST2");
          ret = true;
        }catch(Exception pee){}                 
        assertTrue("Removing End Entity Profile failed", ret);
        
        log.debug("<test05removeEndEntityProfiles()");
    }
    
    
}
