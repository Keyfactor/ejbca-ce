package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import java.security.cert.X509Certificate;
import se.anatom.ejbca.ra.GlobalConfiguration;


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
    
    public boolean isAuthorized(AdminInformation admininformation, String resource) throws AuthorizationDeniedException;
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException;     
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean addAdminGroup(String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAdminGroup(String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public boolean renameAdminGroup(String oldname, String newname);
 
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public AdminGroup getAdminGroup(String name);
        
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAdminGroups();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
     public String[] getAdminGroupnames();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AdminGroup[] getAdminGroups();

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAccessRule(String admingroupname, String resource, int rule, boolean recursive);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAccessRule(String admingroupname, String resource);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAccessRules(String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AccessRule[] getAccessRules(String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    
    public void addAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue);    
    
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public void removeAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public int getNumberOfAdminEntities(String admingroupname);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */ 
    public AdminEntity[] getAdminEntities(String admingroupname);


           
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

    /**
     * @see se.anatom.ejbca.ra.raadmin.IAuthorizationSessionRemote
     */     
    public boolean existsEndEntityProfileInRules(int profileid);
       
}

