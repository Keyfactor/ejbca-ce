package se.anatom.ejbca.ra.raadmin;


import java.rmi.RemoteException;
import java.util.Collection;

import se.anatom.ejbca.webdist.rainterface.Profile;
/**

 * For docs, see ProfileGroupDataBean

 **/

public interface ProfileGroupDataLocal extends javax.ejb.EJBLocalObject {

    // public methods

    public String getProfileGroupName();

    public void setProfileGroupName(String profilegroupname);

    /**
     * Adds a profile to the database.
     *
     * @return false if profilename already exists. 
     */        
    
    public boolean addProfile(String profilename, Profile profile);    
    
     /**
     * Adds a profile to a group with the same content as the original profile, 
     *  
     * @return false if the new profilename already exists.   
     */ 
    public boolean cloneProfile(String originalprofilename, String newprofilename);
    
     /**
     * Removes a profile from the database. 
     * 
     */ 
    public void removeProfile(String profilename);
    
     /**
     * Renames a profile
     *
     * @return false if new name already exists         
     */ 
    public boolean renameProfile(String oldprofilename, String newprofilename);   

    /**
     * Updates profile data
     *
     * @return false if profilename doesn't exists
     */     
    
    public boolean changeProfile(String profilename, Profile profile); 
        
     
      /**
       * Returns the available profile names i current profilegroup.
       *
       * @return A collection of profilenames in the group
       */       
    public Collection getProfileNames();
      /**
       * Returns the available profile group names.
       *
       * @return A collection of profiles in the group
       */        
    public Collection getProfiles();
    
      /**
       * Returns the available profile group names.
       *
       * @return the profile data or null if profile doesn't exists.
       */         
    public Profile getProfile(String profilename);
    
}

