package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import java.security.cert.X509Certificate;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IAuthorizationSessionRemote for docs.
 *
 * @version $Id: IAuthorizationSessionLocal .java
 * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
 */

public interface IAuthorizationSessionLocal extends javax.ejb.EJBLocalObject
{
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public boolean isAuthorized(UserInformation userinformation, String resource) throws AuthorizationDeniedException;
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException;     
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean addUserGroup(String usergroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeUserGroup(String usergroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean renameUserGroup(String oldname, String newname);
 
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public UserGroup getUserGroup(String name);
        
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfUserGroups();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
     public String[] getUserGroupnames();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public UserGroup[] getUserGroups();

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAccessRule(String usergroupname, String directory, int rule, boolean recursive);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAccessRule(String usergroupname, String directory);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAccessRules(String usergroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AccessRule[] getAccessRules(String usergroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfUserEntities(String usergroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public UserEntity[] getUserEntities(String usergroupname);


           
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

