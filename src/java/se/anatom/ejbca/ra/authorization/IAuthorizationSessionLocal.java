package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import java.security.cert.X509Certificate;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.log.Admin;


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
     public void init(GlobalConfiguration globalconfiguration);
     
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public boolean isAuthorized(AdminInformation admininformation, String resource) throws AuthorizationDeniedException;
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException;     
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean addAdminGroup(Admin admin, String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAdminGroup(Admin admin, String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean renameAdminGroup(Admin admin, String oldname, String newname);
 
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public AdminGroup getAdminGroup(Admin admin, String name);
        
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAdminGroups(Admin admin);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
     public String[] getAdminGroupnames(Admin admin);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AdminGroup[] getAdminGroups(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAccessRule(Admin admin, String admingroupname, String resource, int rule, boolean recursive);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAccessRule(Admin admin, String admingroupname, String resource);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAccessRules(Admin admin, String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AccessRule[] getAccessRules(Admin admin, String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype, String matchvalue);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype, String matchvalue);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAdminEntities(Admin admin, String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AdminEntity[] getAdminEntities(Admin admin, String admingroupname);


           
    // Methods used with AvailableAccessRulesData Entity beans.
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 

    public void addAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAvailableAccessRules(Admin admin, Collection names);    
 
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 

    public void removeAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void removeAvailableAccessRules(Admin admin, Collection names);   

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public Collection getAvailableAccessRules(Admin admin);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public boolean existsAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */     
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid);
       
}

