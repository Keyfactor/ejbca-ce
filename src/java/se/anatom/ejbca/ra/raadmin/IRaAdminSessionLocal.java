

package se.anatom.ejbca.ra.raadmin;


import java.math.BigInteger;
import java.util.Collection;
import java.util.TreeMap;
import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
import se.anatom.ejbca.webdist.webconfiguration.UserPreference;
import se.anatom.ejbca.webdist.rainterface.Profile;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IRaAdminSessionLocal .java
 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
 */

public interface IRaAdminSessionLocal extends javax.ejb.EJBLocalObject

{
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 

    public void saveGlobalConfiguration(GlobalConfiguration globalconfiguration);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 

    public GlobalConfiguration loadGlobalConfiguration();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public UserPreference getUserPreference(BigInteger serialnumber);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean addUserPreference(BigInteger serialnumber, UserPreference userpreference);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean changeUserPreference(BigInteger serialnumber, UserPreference userpreference);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean existsUserPreference(BigInteger serialnumber);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean addProfileGroup(String profilegroupname);
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean cloneProfileGroup(String originalprofilegroupname, String newprofilegroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public void removeProfileGroup(String profilegroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean renameProfileGroup(String oldprofilegroupname, String newprofilegroupname);   
       
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */    
    
    public boolean addProfile(String Groupname, String profilename, Profile profile);   
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean cloneProfile(String profilegroupname, String originalprofilename, String newprofilename);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public void removeProfile(String profilegroupname, String profilename);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean renameProfile(String profilegroupnamme, String oldprofilename, String newprofilename);   

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */ 
    
    public boolean changeProfile(String profilegroupnamme, String profilename, Profile profile); 
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */      
    public Collection getProfileGroupNames();  
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */       
    public Collection getProfileNames(String profilegroupname);
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */     
    public TreeMap getProfiles(String profilegroupname);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */    
    public Profile getProfile(String profilegroupname, String profilename);
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */        
    public int getNumberOfProfileGroups();
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSession
     */      
    public int getNumberOfProfiles(String profilegroupname);
    
}

