package se.anatom.ejbca.ca.store.junit;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;

/**
 * Tests the certificate profile entity bean.
 *
 * @version $Id: TestCertificateProfile.java,v 1.1 2004-03-14 13:50:07 herrvendil Exp $
 */
public class TestCertificateProfile extends TestCase {
	private static Logger log = Logger.getLogger(TestCertificateProfile.class);
    private ICertificateStoreSessionRemote cacheAdmin;


    private static ICertificateStoreSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCertificateProfile object.
     *
     * @param name name
     */
    public TestCertificateProfile(String name) {
        super(name);
    }

    protected void setUp() throws Exception  {

        log.debug(">setUp()");

        if( cacheAdmin == null ) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CertificateStoreSession");
                cacheHome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);                
                
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
     * adds a profile to the database
     *
     * @throws Exception error
     */
    public void test01AddCertificateProfile() throws Exception {
        log.debug(">test01AddCertificateProfile()");
        boolean ret = false;
        try{
          CertificateProfile profile = new CertificateProfile();
          profile.setCRLDistributionPointURI("TEST");
                    
          cacheAdmin.addCertificateProfile(admin, "TEST",profile);
          
          ret = true;
        }catch(CertificateProfileExistsException pee){}
                 
        assertTrue("Creating Certificate Profile failed", ret); 
        log.debug("<test01AddCertificateProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameCertificateProfile() throws Exception {
        log.debug(">test02RenameCertificateProfile()");

        boolean ret = false;
        try{                      
          cacheAdmin.renameCertificateProfile(admin, "TEST", "TEST2");          
          ret = true;
        }catch(CertificateProfileExistsException pee){}                 
        assertTrue("Renaming Certificate Profile failed", ret);
                
        log.debug("<test02RenameCertificateProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneCertificateProfile() throws Exception {
        log.debug(">test03CloneCertificateProfile()");

        boolean ret = false;
        try{                      
          cacheAdmin.cloneCertificateProfile(admin, "TEST2", "TEST");          
          ret = true;
        }catch(CertificateProfileExistsException pee){}                 
        assertTrue("Cloning Certificate Profile failed", ret);        
        
        log.debug("<test03CloneCertificateProfile()");
    }
    
    
    
    /**
     * edits profile
     *
     * @throws Exception error
     */	
    public void test04EditCertificateProfile() throws Exception {
    	log.debug(">test04EditCertificateProfile()");

        boolean ret = false;
        
        CertificateProfile profile = cacheAdmin.getCertificateProfile(admin, "TEST");
        assertTrue("Retrieving CertificateProfile failed", profile.getCRLDistributionPointURI().equals("TEST"));
        
        profile.setCRLDistributionPointURI("TEST2");
        
        cacheAdmin.changeCertificateProfile(admin, "TEST", profile);                    
        ret = true;
                         
        assertTrue("Editing CertificateProfile failed", ret);        

    	
    	
    	log.debug("<test04EditCertificateProfile()");
    }
    
         
    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeCertificateProfiles() throws Exception {
        log.debug(">test05removeCertificateProfiles()");        
        boolean ret = false;
        try{
          cacheAdmin.removeCertificateProfile(admin,"TEST");
          cacheAdmin.removeCertificateProfile(admin,"TEST2");
          ret = true;
        }catch(Exception pee){}                 
        assertTrue("Removing Certificate Profile failed", ret);
        
        log.debug("<test05removeCertificateProfiles()");
    }
    
    
}
