package se.anatom.ejbca.ra.authorization;
import java.util.Collection;

import java.rmi.RemoteException;
import javax.ejb.FinderException;



/**
 *
 * @version $Id: IAuthorizationSessionRemote.java,v 1.1 2002-06-27 10:57:34 herrvendil Exp $
 */
public interface IAuthorizationSessionRemote extends javax.ejb.EJBObject {
    // Methods used with AvailableAccessRulesData Entity beans.
    
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

