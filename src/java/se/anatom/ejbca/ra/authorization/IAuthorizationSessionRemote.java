package se.anatom.ejbca.ra.authorization;
import java.util.Collection;
import java.security.cert.X509Certificate;

import java.rmi.RemoteException;
import javax.ejb.FinderException;
import se.anatom.ejbca.ra.GlobalConfiguration;


/**
 *
 * @version $Id: IAuthorizationSessionRemote.java,v 1.6 2002-10-24 20:07:06 herrvendil Exp $
 */
public interface IAuthorizationSessionRemote extends javax.ejb.EJBObject {
    

    // Methods used with AvailableAccessRulesData Entity beans.
    
    /** 
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admininformation can be a certificate or special user, see AdminInformation class.
     * 
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource) throws RemoteException, AuthorizationDeniedException;
    
    /** 
     * Method to validate, verify and check revokation of a users certificate.
     *
     * @param certificate the users X509Certificate.
     * 
     */
    
    public void authenticate(X509Certificate certificate) throws RemoteException, AuthenticationFailedException;    
    
   /** 
    * Method to add an admingroup. 
    *
    * @return  False if admingroup already exists  
    */
    public boolean addAdminGroup(String admingroupname) throws RemoteException;
    
    /** 
     * Method to remove a admingroup.
     */ 
    public void removeAdminGroup(String admingroupname) throws RemoteException;
    
    /**
     * Metod to rename a admingroup
     *
     * @return false if new admingroup already exists.
     */
    public boolean renameAdminGroup(String oldname, String newname) throws RemoteException;
 
    
    /** 
     * Method to get a reference to a admingroup.
     */
    
    public AdminGroup getAdminGroup(String name)  throws RemoteException;
        
    /** 
     * Returns the number of admingroups
     */
    public int getNumberOfAdminGroups()  throws RemoteException;
    
    /** 
     *Returns an array containing all the admingroups names.
     */
     public String[] getAdminGroupnames() throws RemoteException;
    
    /** 
     * Returns an array containing all the admingroups.
     */
    public AdminGroup[] getAdminGroups() throws RemoteException;

     /**
     * Removes an accessrule from the admingroup. 
     * 
     */ 
    
    public void addAccessRule(String admingroupname, String resource, int rule, boolean recursive)  throws RemoteException;    
    
    
     /**
     * Removes an accessrule from the database. 
     * 
     */ 
    public void removeAccessRule(String admingroupname, String resource)  throws RemoteException;
    
     /**
     * Returns the number of access rules in admingroup
     *
     * @return the number of accessrules in the admingroup    
     */ 
    public int getNumberOfAccessRules(String admingroupname)  throws RemoteException;
    
     /**
      * Returns all the accessrules in the admingroup as an array of AccessRule
      *
      */
    public AccessRule[] getAccessRules(String admingroupname)  throws RemoteException;
    
     /**
     * Adds a user entity to the admingroup. Changes it's values if it already exists
     *
     */        
    
    public void addAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue) throws RemoteException;    
    
    
     /**
     * Removes a user entity from the admingroup. 
     * 
     */ 
    public void removeAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue) throws RemoteException;
    
     /**
     * Returns the number of user entities in admingroup
     *
     * @return the number of user entities in the database for the specified group    
     */ 
    public int getNumberOfAdminEntities(String admingroupname) throws RemoteException;
    
     /**
      * Returns all the AdminEntities as an array of AdminEntities for the specified group.
      *
      */
    public AdminEntity[] getAdminEntities(String admingroupname) throws RemoteException;

    /**
     * Method to add an access rule.
     */ 

    public void addAvailableAccessRule(String name) throws RemoteException;

    /**
     * Method to add a Collection of access rules.
     */ 
    
    public void addAvailableAccessRules(Collection names) throws RemoteException;    
 
    /**
     * Method to remove an access rule.
     */ 

    public void removeAvailableAccessRule(String name) throws RemoteException;

    /**
     * Method to add a Collection of access rules.
     */ 
    
    public void removeAvailableAccessRules(Collection names) throws RemoteException;    

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */ 
    
    public Collection getAvailableAccessRules() throws RemoteException;
    
    /**
     * Checks wheither an access rule exists in the database.
     */ 
    
    public boolean existsAvailableAccessRule(String name) throws RemoteException;
    
     /** 
     * Method to check if a profile exists in any profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    
    public boolean existsEndEntityProfileInRules(int profileid) throws RemoteException;
    
}

