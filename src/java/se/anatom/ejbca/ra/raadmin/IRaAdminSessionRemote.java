package se.anatom.ejbca.ra.raadmin;
import java.util.Collection;
import java.util.TreeMap;
import java.math.BigInteger;

import java.rmi.RemoteException;
import javax.ejb.FinderException;


import se.anatom.ejbca.ra.raadmin.UserPreference;
import se.anatom.ejbca.ra.raadmin.Profile;

/**
 *
 * @version $Id: IRaAdminSessionRemote.java,v 1.4 2002-07-20 18:40:08 herrvendil Exp $
 */
public interface IRaAdminSessionRemote extends javax.ejb.EJBObject {
    
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
     * Adds a profile to the database.
     *
     * @return false if profilename already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addProfile(String profilename, Profile profile) throws RemoteException;   
    
     /**
     * Adds a profile  with the same content as the original profile, 
     *  
     * @return false if the new profilename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneProfile(String originalprofilename, String newprofilename) throws RemoteException;
    
     /**
     * Removes a profile from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeProfile(String profilename) throws RemoteException;
    
     /**
     * Renames a profile
     *
     * @return false if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameProfile(String oldprofilename, String newprofilename) throws RemoteException;   

    /**
     * Updates profile data
     *
     * @return false if profilename doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeProfile(String profilename, Profile profile) throws RemoteException; 
    
      /**
       * Returns the available profile names.
       *
       * @return A collection of profilenames.
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getProfileNames() throws RemoteException;
      /**
       * Returns the available profiles.
       *
       * @return A collection of Profiles.
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getProfiles() throws RemoteException;
    
      /**
       * Returns the specified profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public Profile getProfile(String profilename) throws RemoteException;
    
       /**
       * Returns the specified profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public Profile getProfile(int id) throws RemoteException;

      /**
       * Returns the available profiles.
       *
       * @return the available profiles.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfProfiles() throws RemoteException;
    
      /**
       * Returns a profiles id given it´s profilename.
       *
       * @return id number of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getProfileId(String profilename) throws RemoteException;
    
       /**
       * Returns a profiles name given it´s id.
       *
       * @return the name of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getProfileName(int id) throws RemoteException;    
}

