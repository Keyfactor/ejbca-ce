package se.anatom.ejbca.ra.authorization;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.GlobalConfiguration;

import java.rmi.RemoteException;

import java.security.cert.X509Certificate;

import java.util.Collection;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IAuthorizationSessionRemote.java,v 1.10 2003-06-26 11:43:25 anatom Exp $
 */
public interface IAuthorizationSessionRemote extends javax.ejb.EJBObject {
    // Methods used with AvailableAccessRulesData Entity beans.

    /**
     * Method to initialize authorization bean, must be called directly after creation of bean.
     */
    public void init(GlobalConfiguration globalconfiguration)
        throws RemoteException;

    /**
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admininformation can be a certificate or special user, see AdminInformation class.
     *
     * @return DOCUMENT ME!
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource)
        throws RemoteException, AuthorizationDeniedException;

    /**
     * Method to check if a user is authorized to a certain resource without performing any
     * logging.
     *
     * @param admininformation can be a certificate or special user, see AdminInformation class.
     *
     * @return DOCUMENT ME!
     */
    public boolean isAuthorizedNoLog(AdminInformation admininformation, String resource)
        throws RemoteException, AuthorizationDeniedException;

    /**
     * Method to validate, verify and check revokation of a users certificate.
     *
     * @param certificate the users X509Certificate.
     */
    public void authenticate(X509Certificate certificate)
        throws RemoteException, AuthenticationFailedException;

    /**
     * Method to add an admingroup.
     *
     * @return False if admingroup already exists
     */
    public boolean addAdminGroup(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Metod to rename a admingroup
     *
     * @return false if new admingroup already exists.
     */
    public boolean renameAdminGroup(Admin admin, String oldname, String newname)
        throws RemoteException;

    /**
     * Method to get a reference to a admingroup.
     *
     * @return DOCUMENT ME!
     */
    public AdminGroup getAdminGroup(Admin admin, String name)
        throws RemoteException;

    /**
     * Returns the number of admingroups
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfAdminGroups(Admin admin) throws RemoteException;

    /**
     * Returns an array containing all the admingroups names.
     *
     * @return DOCUMENT ME!
     */
    public String[] getAdminGroupnames(Admin admin) throws RemoteException;

    /**
     * Returns an array containing all the admingroups.
     *
     * @return DOCUMENT ME!
     */
    public AdminGroup[] getAdminGroups(Admin admin) throws RemoteException;

    /**
     * Removes an accessrule from the admingroup.
     */
    public void addAccessRule(Admin admin, String admingroupname, String resource, int rule,
        boolean recursive) throws RemoteException;

    /**
     * Removes an accessrule from the database.
     */
    public void removeAccessRule(Admin admin, String admingroupname, String resource)
        throws RemoteException;

    /**
     * Returns the number of access rules in admingroup
     *
     * @return the number of accessrules in the admingroup
     */
    public int getNumberOfAccessRules(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Returns all the accessrules in the admingroup as an array of AccessRule
     *
     * @return DOCUMENT ME!
     */
    public AccessRule[] getAccessRules(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Adds a user entity to the admingroup. Changes it's values if it already exists
     */
    public void addAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype,
        String matchvalue) throws RemoteException;

    /**
     * Removes a user entity from the admingroup.
     */
    public void removeAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype,
        String matchvalue) throws RemoteException;

    /**
     * Returns the number of user entities in admingroup
     *
     * @return the number of user entities in the database for the specified group
     */
    public int getNumberOfAdminEntities(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Returns all the AdminEntities as an array of AdminEntities for the specified group.
     *
     * @return DOCUMENT ME!
     */
    public AdminEntity[] getAdminEntities(Admin admin, String admingroupname)
        throws RemoteException;

    /**
     * Method to add an access rule.
     */
    public void addAvailableAccessRule(Admin admin, String name)
        throws RemoteException;

    /**
     * Method to add a Collection of access rules.
     */
    public void addAvailableAccessRules(Admin admin, Collection names)
        throws RemoteException;

    /**
     * Method to remove an access rule.
     */
    public void removeAvailableAccessRule(Admin admin, String name)
        throws RemoteException;

    /**
     * Method to add a Collection of access rules.
     */
    public void removeAvailableAccessRules(Admin admin, Collection names)
        throws RemoteException;

    /**
     * Method that returns a Collection of Strings containing all access rules.
     *
     * @return DOCUMENT ME!
     */
    public Collection getAvailableAccessRules(Admin admin)
        throws RemoteException;

    /**
     * Checks wheither an access rule exists in the database.
     *
     * @return DOCUMENT ME!
     */
    public boolean existsAvailableAccessRule(Admin admin, String name)
        throws RemoteException;

    /**
     * Method to check if a profile exists in any profile rules. Used to avoid desyncronization of
     * profilerules.
     *
     * @param profileid the profile id to search for.
     *
     * @return true if profile exists in any of the accessrules.
     */
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid)
        throws RemoteException;
}
