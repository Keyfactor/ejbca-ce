package se.anatom.ejbca.ra.raadmin;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.log.Admin;

/**
 *
 * @version $Id: IRaAdminSessionRemote.java,v 1.15 2004-01-31 14:24:59 herrvendil Exp $
 */
public interface IRaAdminSessionRemote extends javax.ejb.EJBObject {
    
    public final static String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILENAME;
    
    
    public AdminPreference getAdminPreference(Admin admin, String certificatefingerprint) throws RemoteException;

    /**
     * Adds a admin preference to the database.
     *
     * @return false if admin already exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean addAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference) throws RemoteException;
    
    /**
     * Changes the admin preference in the database.
     *
     * @return false if admin doesn't exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean changeAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference) throws RemoteException;
 
    
    /**
     * Changes the admin preference in the database. Without performing any logging.
     *
     * @return false if admin doesn't exists.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean changeAdminPreferenceNoLog(Admin admin, String certificatefingerprint, AdminPreference adminpreference) throws RemoteException;
    
    /**
     * Checks if a admin preference exists in the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */ 
    
    public boolean existsAdminPreference(Admin admin, String certificatefingerprint) throws RemoteException;

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
     * @throws EndEntityProfileExistsException if profilename already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    public void addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException, RemoteException; 
    
    /**
     * Adds a end entity profile to the database.
     *
     * @param admin administrator performing task
     * @param profileid internal ID of new profile, use only if you know it's right.
     * @param profilename readable profile name
     * @param profile profile to be added
     *
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public void addEndEntityProfile(Admin admin, int profileid, String profilename, EndEntityProfile profile)
        throws EndEntityProfileExistsException, RemoteException;     
      
    
     /**
     * Adds a end entity profile  with the same content as the original profile, 
     *  
     * @throws EndEntityProfileExistsException if the new profilename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public void cloneEndEntityProfile(Admin admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException, RemoteException;
    
     /**
     * Removes a end entity profile from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeEndEntityProfile(Admin admin, String profilename) throws RemoteException;
    
     /**
     * Renames a end entity profile
     *
     * @throws EndEntityProfileExistsException if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public void renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException, RemoteException;   

    /**
     * Updates end entity profile data
     *
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public void changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws RemoteException; 
    
      /**
       * Returns the end entity profile id of all authorized profiles. 
       * The authorization control currently checks if administrator have access to all CA:s in profile.
       *
       * @return A collection of profileid (Integer)
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getAuthorizedEndEntityProfileIds(Admin admin) throws RemoteException;
    
    
    /**
     * Returns a EndEntityProfileId to Name mao
     */
    public HashMap getEndEntityProfileIdToNameMap(Admin admin) throws RemoteException;

     /**
       * Returns the specified profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public EndEntityProfile getEndEntityProfile(Admin admin, int id) throws RemoteException;

     /**
       * Returns the specified profile.
       *
       * @return the profile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename) throws RemoteException;    
    
    
      /**
       * Returns a profiles id given it's profilename.
       *
       * @return id number of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getEndEntityProfileId(Admin admin, String profilename) throws RemoteException;
    
       /**
       * Returns a profiles name given it's id.
       *
       * @return the name of profile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getEndEntityProfileName(Admin admin, int id) throws RemoteException;    
    
     /** 
     * Method to check if a certificateprofile exists in any of the profiles. Used to avoid desyncronization of profile data.
     *
     * @param certificateprofileid the certificateprofile id to search for.
     * @return true if certificateprofile exists in any of the end entity profiles.
     */
    
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid) throws RemoteException;

     /** 
     * Method to check if a caid exists in any of the profiles. Used to avoid desyncronization of CA data.
     *
     * @param caid the CA id to search for.
     * @return true if caid exists in any of the end entity profiles.
     */
    
    public boolean existsCAInEndEntityProfiles(Admin admin, int caid) throws RemoteException;

    
     /**
      * Saves global configuration to the database.
      *
      * @throws EJBException if a communication or other error occurs.
      */
    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globalconfiguration) throws RemoteException;

     /**
      * Loads the global configuration from the database.
      *
      * @throws EJBException if a communication or other error occurs.
      */
    public GlobalConfiguration loadGlobalConfiguration(Admin admin) throws RemoteException;
    
    /**
     * Sets the base url in the global configuration.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void initGlobalConfigurationBaseURL(Admin admin, String computername, String applicationpath) throws RemoteException;

}

