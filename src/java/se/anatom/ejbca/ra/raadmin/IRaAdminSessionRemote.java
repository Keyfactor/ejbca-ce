package se.anatom.ejbca.ra.raadmin;
import java.util.Collection;
import java.util.TreeMap;
import java.math.BigInteger;

import java.rmi.RemoteException;
import javax.ejb.FinderException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
import se.anatom.ejbca.webdist.webconfiguration.UserPreference;
import se.anatom.ejbca.webdist.rainterface.Profile;

/**
 *
 * @version $Id: IRaAdminSessionRemote.java,v 1.3 2002-06-27 10:57:34 herrvendil Exp $
 */
public interface IRaAdminSessionRemote extends javax.ejb.EJBObject {

    
    // Functions used by Global Configuration
   /**
    * Saves global configuration to the database.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void saveGlobalConfiguration(GlobalConfiguration globalconfiguration) throws RemoteException;

   /**
    * Loads the global configuration from the database.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException;
    
    
    // Functions used by User Preferences
     /**
     * Finds the userpreference belonging to a certificate serialnumber
     * 
     * @return the users userpreferences.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public UserPreference getUserPreference(BigInteger serialnumber) throws RemoteException;

    /**
     * Adds a user preference to the database.
     *
     * @return false if user already exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean addUserPreference(BigInteger serialnumber, UserPreference userpreference) throws RemoteException;
    
    /**
     * Changes the userpreference in the database.
     *
     * @return false if user doesn't exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean changeUserPreference(BigInteger serialnumber, UserPreference userpreference) throws RemoteException;
    
    /**
     * Checks if a userpreference exists in the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean existsUserPreference(BigInteger serialnumber) throws RemoteException;

    
    // Functions used by Profiles
    
     /**
     * Adds a profile group to the database
     * 
     * @return returns false if groupname already exists.
     * @throws EJBException if a communication or other error occurs.
     */    
    
    public boolean addProfileGroup(String profilegroupname) throws RemoteException;
    
    
    /**
     * Adds a profile group with the same content as the original profile, 
     * 
     * @return false if the new profile groupname already exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    public boolean cloneProfileGroup(String originalprofilegroupname, String newprofilegroupname) throws RemoteException;
    
    /**
     * Removes a profile group from the database. 
     *
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeProfileGroup(String profilegroupname) throws RemoteException;
    
     /**
     * Renames a profile group
     *
     * @return false if new groupname already exists
     * @throws EJBException if a communication or other error occurs.    
     */ 
    public boolean renameProfileGroup(String oldprofilegroupname, String newprofilegroupname) throws RemoteException;   
       
    /**
     * Adds a profile to the database.
     *
     * @return false if profilename already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addProfile(String Groupname, String profilename, Profile profile) throws RemoteException;   
    
     /**
     * Adds a profile to a group with the same content as the original profile, 
     *  
     * @return false if the new profilename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneProfile(String profilegroupname, String originalprofilename, String newprofilename) throws RemoteException;
    
     /**
     * Removes a profile from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeProfile(String profilegroupname, String profilename) throws RemoteException;
    
     /**
     * Renames a profile
     *
     * @return false if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameProfile(String profilegroupnamme, String oldprofilename, String newprofilename) throws RemoteException;   

    /**
     * Updates profile data
     *
     * @return false if profilename doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeProfile(String profilegroupnamme, String profilename, Profile profile) throws RemoteException; 
    
      /**
       * Returns the available profile group names.
       *
       * @return Available group names as a Collection of Strings.
       * @throws EJBException if a communication or other error occurs.
       */      
    public Collection getProfileGroupNames() throws RemoteException;  
      /**
       * Returns the available profile group names.
       *
       * @return A collection of profilenames in the group
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getProfileNames(String profilegroupname) throws RemoteException;
      /**
       * Returns the available profile group names.
       *
       * @return A collection of profiles in the group
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getProfiles(String profilegroupname) throws RemoteException;
    
      /**
       * Returns the available profile group names.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public Profile getProfile(String profilegroupname, String profilename) throws RemoteException;
      /**
       * Returns the number of profile groups.
       *
       * @return the number of profile groups.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfProfileGroups() throws RemoteException;
      /**
       * Returns the available profiles in a group.
       *
       * @return the available profiles in tje group.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfProfiles(String profilegroupname) throws RemoteException;
}

