package se.anatom.ejbca.ra.raadmin;
import java.util.Collection;
import java.util.TreeMap;
import java.math.BigInteger;

import java.rmi.RemoteException;

import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.log.Admin;

/**
 *
 * @version $Id: IRaAdminSessionRemote.java,v 1.9 2003-01-12 17:16:33 anatom Exp $
 */
public interface IRaAdminSessionRemote extends javax.ejb.EJBObject {
    
    public final static String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE;
    
    
    public AdminPreference getAdminPreference(Admin admin, BigInteger serialnumber) throws RemoteException;

    /**
     * Adds a admin preference to the database.
     *
     * @return false if admin already exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean addAdminPreference(Admin admin, BigInteger serialnumber, AdminPreference adminpreference) throws RemoteException;
    
    /**
     * Changes the admin preference in the database.
     *
     * @return false if admin doesn't exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean changeAdminPreference(Admin admin, BigInteger serialnumber, AdminPreference adminpreference) throws RemoteException;
    
    /**
     * Checks if a admin preference exists in the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean existsAdminPreference(Admin admin, BigInteger serialnumber) throws RemoteException;

    /**
     * Function that returns the default admin preference.
     *
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public AdminPreference getDefaultAdminPreference(Admin admin) throws RemoteException;
    
     /**
     * Function that saves the default admin preference.
     *
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference) throws RemoteException;   
    
    // Functions used by EndEntityProfiles
           
    /**
     * Adds a end entity profile to the database.
     *
     * @return false if profilename already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws RemoteException;   
    
     /**
     * Adds a end entity profile  with the same content as the original profile, 
     *  
     * @return false if the new profilename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneEndEntityProfile(Admin admin, String originalprofilename, String newprofilename) throws RemoteException;
    
     /**
     * Removes a end entity profile from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeEndEntityProfile(Admin admin, String profilename) throws RemoteException;
    
     /**
     * Renames a end entity profile
     *
     * @return false if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) throws RemoteException;   

    /**
     * Updates end entity profile data
     *
     * @return false if profilename doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws RemoteException; 
    
      /**
       * Returns the available end entity profile names.
       *
       * @return A collection of profilenames.
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getEndEntityProfileNames(Admin admin) throws RemoteException;
      /**
       * Returns the available end entity profiles.
       *
       * @return A collection of EndEntityProfiles.
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getEndEntityProfiles(Admin admin) throws RemoteException;
    
      /**
       * Returns the specified end entity profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename) throws RemoteException;
    
       /**
       * Returns the specified profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public EndEntityProfile getEndEntityProfile(Admin admin, int id) throws RemoteException;

      /**
       * Returns the available profiles.
       *
       * @return the available profiles.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfEndEntityProfiles(Admin admin) throws RemoteException;
    
      /**
       * Returns a profiles id given it?s profilename.
       *
       * @return id number of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getEndEntityProfileId(Admin admin, String profilename) throws RemoteException;
    
       /**
       * Returns a profiles name given it?s id.
       *
       * @return the name of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getEndEntityProfileName(Admin admin, int id) throws RemoteException;    
    
     /** 
     * Method to check if a certificatetype exists in any of the profiles. Used to avoid desyncronization of profile data.
     *
     * @param certificatetypeid the certificatetype id to search for.
     * @return true if certificatetype exists in any of the accessrules.
     */
    
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid) throws RemoteException;
}

