package se.anatom.ejbca.ra.authorization;

import java.util.Collection;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IAuthorizationSessionRemote for docs.
 *
 * @version $Id: IAuthorizationSessionLocal .java
 * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
 */

public interface IAuthorizationSessionLocal extends javax.ejb.EJBLocalObject

{
    
    // Methods used with AvailableAccessRulesData Entity beans.
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 

    public void addAvailableAccessRule(String name);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAvailableAccessRules(Collection names);    
 
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 

    public void removeAvailableAccessRule(String name);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void removeAvailableAccessRules(Collection names);   

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public Collection getAvailableAccessRules();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public boolean existsAvailableAccessRule(String name);
       
}

