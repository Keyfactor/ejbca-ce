package se.anatom.ejbca.ra.authorization;
import java.util.Collection;

import java.rmi.RemoteException;
import javax.ejb.FinderException;



/**
 *
 * @version $Id: IAuthorizationSessionRemote.java,v 1.2 2002-07-04 13:03:17 herrvendil Exp $
 */
public interface IAuthorizationSessionRemote extends javax.ejb.EJBObject {
    // Methods used with AvailableAccessRulesData Entity beans.
    
   /** 
    * Method to add an usergroup. 
    *
    * @return  False if usergroup already exists  
    */
    public boolean addUserGroup(String usergroupname) throws RemoteException;
    
    /** 
     * Method to remove a usergroup.
     */ 
    public void removeUserGroup(String usergroupname) throws RemoteException;
    
    /**
     * Metod to rename a usergroup
     *
     * @return false if new usergroup already exists.
     */
    public boolean renameUserGroup(String oldname, String newname) throws RemoteException;
 
    
    /** 
     * Method to get a reference to a usergroup.
     */
    
    public UserGroup getUserGroup(String name)  throws RemoteException;
        
    /** 
     * Returns the number of usergroups
     */
    public int getNumberOfUserGroups()  throws RemoteException;
    
    /** 
     *Returns an array containing all the usergroups names.
     */
     public String[] getUserGroupnames() throws RemoteException;
    
    /** 
     * Returns an array containing all the usergroups.
     */
    public UserGroup[] getUserGroups() throws RemoteException;

     /**
     * Removes an accessrule from the usergroup. 
     * 
     */ 
    
    public void addAccessRule(String usergroupname, String directory, int rule, boolean recursive)  throws RemoteException;    
    
    
     /**
     * Removes an accessrule from the database. 
     * 
     */ 
    public void removeAccessRule(String usergroupname, String directory)  throws RemoteException;
    
     /**
     * Returns the number of access rules in usergroup
     *
     * @return the number of accessrules in the usergroup    
     */ 
    public int getNumberOfAccessRules(String usergroupname)  throws RemoteException;
    
     /**
      * Returns all the accessrules in the usergroup as an array of AccessRule
      *
      */
    public AccessRule[] getAccessRules(String usergroupname)  throws RemoteException;
    
     /**
     * Adds a user entity to the usergroup. Changes it's values if it already exists
     *
     */        
    
    public void addUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue) throws RemoteException;    
    
    
     /**
     * Removes a user entity from the usergroup. 
     * 
     */ 
    public void removeUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue) throws RemoteException;
    
     /**
     * Returns the number of user entities in usergroup
     *
     * @return the number of user entities in the database for the specified group    
     */ 
    public int getNumberOfUserEntities(String usergroupname) throws RemoteException;
    
     /**
      * Returns all the UserEntities as an array of UserEntities for the specified group.
      *
      */
    public UserEntity[] getUserEntities(String usergroupname) throws RemoteException;

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
    
}

