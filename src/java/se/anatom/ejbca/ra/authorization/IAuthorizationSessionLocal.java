package se.anatom.ejbca.ra.authorization;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.GlobalConfiguration;

import java.security.cert.X509Certificate;

import java.util.Collection;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IAuthorizationSessionRemote for docs.
 *
 * @version $Id: IAuthorizationSessionLocal .java
 *
 * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
 */
public interface IAuthorizationSessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void init(GlobalConfiguration globalconfiguration);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource)
        throws AuthorizationDeniedException;

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean isAuthorizedNoLog(AdminInformation admininformation, String resource)
        throws AuthorizationDeniedException;

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void authenticate(X509Certificate certificate)
        throws AuthenticationFailedException;

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean addAdminGroup(Admin admin, String admingroupname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void removeAdminGroup(Admin admin, String admingroupname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean renameAdminGroup(Admin admin, String oldname, String newname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public AdminGroup getAdminGroup(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public int getNumberOfAdminGroups(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public String[] getAdminGroupnames(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public AdminGroup[] getAdminGroups(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void addAccessRule(Admin admin, String admingroupname, String resource, int rule,
        boolean recursive);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void removeAccessRule(Admin admin, String admingroupname, String resource);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public int getNumberOfAccessRules(Admin admin, String admingroupname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public AccessRule[] getAccessRules(Admin admin, String admingroupname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void addAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype,
        String matchvalue);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void removeAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype,
        String matchvalue);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public int getNumberOfAdminEntities(Admin admin, String admingroupname);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public AdminEntity[] getAdminEntities(Admin admin, String admingroupname);

    // Methods used with AvailableAccessRulesData Entity beans.

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void addAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void addAvailableAccessRules(Admin admin, Collection names);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void removeAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public void removeAvailableAccessRules(Admin admin, Collection names);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public Collection getAvailableAccessRules(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean existsAvailableAccessRule(Admin admin, String name);

    /**
     * @see se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote
     */
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid);
}
