package se.anatom.ejbca.webdist.webconfiguration;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.authorization.*;


/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author Philip Vendil
 * @version $Id: AuthorizationDataHandler.java,v 1.14 2003-07-24 08:43:33 anatom Exp $
 */
public class AuthorizationDataHandler {
    public static final int ACCESS_RULE_RESOURCE = 0;
    public static final int ACCESS_RULE_RULE = 1;
    public static final int ACCESS_RULE_RECURSIVE = 2;
    public static final int ADMIN_ENTITY_MATCHWITH = 0;
    public static final int ADMIN_ENTITY_MATCHTYPE = 1;
    public static final int ADMIN_ENTITY_MATCHVALUE = 2;

    /**
     * Creates a new instance of ProfileDataHandler
     *
     * @param globalconfiguration DOCUMENT ME!
     * @param logsession DOCUMENT ME!
     * @param administrator DOCUMENT ME!
     */
    public AuthorizationDataHandler(GlobalConfiguration globalconfiguration,
        ILogSessionRemote logsession, Admin administrator)
        throws RemoteException, NamingException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                    "AuthorizationSession"), IAuthorizationSessionHome.class);
        authorizationsession = authorizationsessionhome.create();
        authorizationsession.init(globalconfiguration);
        this.administrator = administrator;

        Collection names = authorizationsession.getAvailableAccessRules(administrator);

        if (names.size() == 0) {
            Vector rules = new Vector();
            String[] defaultrules = globalconfiguration.getDefaultAvailableResources();

            for (int i = 0; i < defaultrules.length; i++) {
                rules.addElement(defaultrules[i]);
            }

            authorizationsession.addAvailableAccessRules(administrator, rules);
        }

        availableresources = new AvailableResources(globalconfiguration);
        authorize = new EjbcaAuthorization(getAdminGroups(), globalconfiguration, logsession,
                administrator, LogEntry.MODULE_ADMINWEB);
    }

    // Public methods.

    /**
     * Method to check if a admin is authorized to a resource
     *
     * @param admininformation information about the admin to be authorized.
     * @param resource the resource to look up.
     *
     * @return true if authorizes
     *
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource)
        throws AuthorizationDeniedException {
        return authorize.isAuthorized(admininformation, resource);
    }

    /**
     * Method to check if a admin is authorized to a resource without performing any logging.
     *
     * @param admininformation information about the admin to be authorized.
     * @param resource the resource to look up.
     *
     * @return true if authorizes
     *
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(AdminInformation admininformation, String resource)
        throws AuthorizationDeniedException {
        return authorize.isAuthorizedNoLog(admininformation, resource);
    }

    /**
     * Method that authenticates a certificate by verifying signature, checking validity and lookup
     * if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated.
     *
     * @throws AuthenticationFailedException if authentication failed.
     */
    public void authenticate(X509Certificate certificate)
        throws AuthenticationFailedException {
        authorize.authenticate(certificate);
    }

    // Methods used with admingroup data

    /**
     * Method to add a new admingroup to the access control data.
     *
     * @param name DOCUMENT ME!
     */
    public void addAdminGroup(String name) throws AdmingroupExistsException, RemoteException {
        if (!authorizationsession.addAdminGroup(administrator, name)) {
            throw new AdmingroupExistsException();
        }

        authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
    }

    /**
     * Method to remove a admingroup.
     *
     * @param name DOCUMENT ME!
     */
    public void removeAdminGroup(String name) throws RemoteException {
        authorizationsession.removeAdminGroup(administrator, name);
        authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
    }

    /**
     * Method to rename a admingroup.
     *
     * @param oldname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     */
    public void renameAdminGroup(String oldname, String newname)
        throws AdmingroupExistsException, RemoteException {
        if (!authorizationsession.renameAdminGroup(administrator, oldname, newname)) {
            throw new AdmingroupExistsException();
        }

        authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
    }

    /**
     * Method to retrieve all admingroup's names.
     *
     * @return DOCUMENT ME!
     */
    public String[] getAdminGroupnames() throws RemoteException {
        return authorizationsession.getAdminGroupnames(administrator);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public AdminGroup[] getAdminGroups() throws RemoteException {
        return authorizationsession.getAdminGroups(administrator);
    }

    /**
     * Method to add an array of access rules to a admingroup. The accessrules must be a 2d array
     * where the outer array specifies the field using ACCESS_RULE constants.
     *
     * @param groupname DOCUMENT ME!
     * @param accessrules DOCUMENT ME!
     */
    public void addAccessRules(String groupname, String[][] accessrules)
        throws RemoteException {
        try {
            for (int i = 0; i < accessrules.length; i++) {
                authorizationsession.addAccessRule(administrator, groupname,
                    accessrules[i][ACCESS_RULE_RESOURCE],
                    java.lang.Integer.valueOf(accessrules[i][ACCESS_RULE_RULE]).intValue(),
                    java.lang.Boolean.valueOf(accessrules[i][ACCESS_RULE_RECURSIVE]).booleanValue());
            }

            authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
        } catch (Exception e) {
            // Do not add erronios rules.
        }
    }

    /**
     * Method to remove an array of access rules from a admingroup.
     *
     * @param groupname DOCUMENT ME!
     * @param accessrules DOCUMENT ME!
     */
    public void removeAccessRules(String groupname, String[][] accessrules)
        throws RemoteException {
        int arraysize = accessrules.length;

        try {
            for (int i = 0; i < arraysize; i++) {
                authorizationsession.removeAccessRule(administrator, groupname,
                    accessrules[i][ACCESS_RULE_RESOURCE]);
            }

            authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
        } catch (Exception e) {
            // Do not add erronios rules.
        }
    }

    /**
     * Method that returns all access rules applied to a group.
     *
     * @param groupname DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[][] getAccessRules(String groupname)
        throws RemoteException {
        AccessRule[] accessrules = null;
        String[][] returnarray = null;

        accessrules = authorizationsession.getAccessRules(administrator, groupname);

        if (accessrules != null) {
            returnarray = new String[accessrules.length][3];

            for (int i = 0; i < accessrules.length; i++) {
                returnarray[i][ACCESS_RULE_RESOURCE] = accessrules[i].getResource();
                returnarray[i][ACCESS_RULE_RULE] = String.valueOf(accessrules[i].getRule());
                returnarray[i][ACCESS_RULE_RECURSIVE] = String.valueOf(accessrules[i].isRecursive());
            }
        }

        return returnarray;
    }

    /**
     * Method that returns all avaliable rules to a admingroup. It checks the filesystem for all
     * resources beneaf document root that isn't set hidden or already applied to this group.
     *
     * @param groupname DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[] getAvailableRules(String groupname)
        throws RemoteException {
        return authorizationsession.getAdminGroup(administrator, groupname).nonUsedResources(availableresources.getResources());
    }

    /**
     * Method to add an array of admin entities  to a admingroup. A admin entity van be a single
     * admin or an entire organization depending on how it's match rules i set. The adminentities
     * must be a 2d array where the outer array specifies the fields using USER_ENTITY constants.
     *
     * @param groupname DOCUMENT ME!
     * @param adminentities DOCUMENT ME!
     */
    public void addAdminEntities(String groupname, String[][] adminentities)
        throws RemoteException {
        int arraysize = adminentities.length;

        try {
            for (int i = 0; i < arraysize; i++) {
                authorizationsession.addAdminEntity(administrator, groupname,
                    Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHWITH]),
                    Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHTYPE]),
                    adminentities[i][ADMIN_ENTITY_MATCHVALUE]);
            }

            authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
        } catch (Exception e) {
            // Do not add erroneous rules.
        }
    }

    /**
     * Method to remove an array of admin entities from a admingroup.
     *
     * @param groupname DOCUMENT ME!
     * @param adminentities DOCUMENT ME!
     */
    public void removeAdminEntities(String groupname, String[][] adminentities)
        throws RemoteException {
        int arraysize = adminentities.length;

        try {
            for (int i = 0; i < arraysize; i++) {
                authorizationsession.removeAdminEntity(administrator, groupname,
                    Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHWITH]),
                    Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHTYPE]),
                    adminentities[i][ADMIN_ENTITY_MATCHVALUE]);
            }

            authorize.buildAccessTree(authorizationsession.getAdminGroups(administrator));
        } catch (Exception e) {
            // Do not remove erronios rules.
        }
    }

    /**
     * Method that returns all admin entities belonging to a group.
     *
     * @param groupname DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[][] getAdminEntities(String groupname)
        throws RemoteException {
        AdminEntity[] adminentities;
        String[][] returnarray = null;

        adminentities = authorizationsession.getAdminEntities(administrator, groupname);

        if (adminentities != null) {
            returnarray = new String[adminentities.length][3];

            for (int i = 0; i < adminentities.length; i++) {
                returnarray[i][ADMIN_ENTITY_MATCHWITH] = String.valueOf(adminentities[i].getMatchWith());
                returnarray[i][ADMIN_ENTITY_MATCHTYPE] = String.valueOf(adminentities[i].getMatchType());
                returnarray[i][ADMIN_ENTITY_MATCHVALUE] = adminentities[i].getMatchValue();
            }
        }

        return returnarray;
    }

    // Metods used with available access rules data

    /**
     * Method to add an access rule.
     *
     * @param name DOCUMENT ME!
     */
    public void addAvailableAccessRule(String name) throws RemoteException {
        authorizationsession.addAvailableAccessRule(administrator, name);
    }

    // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     *
     * @param names DOCUMENT ME!
     */
    public void addAvailableAccessRules(Collection names)
        throws RemoteException {
        authorizationsession.addAvailableAccessRules(administrator, names);
    }

    //  addAvailableAccessRules

    /**
     * Method to remove an access rule.
     *
     * @param name DOCUMENT ME!
     */
    public void removeAvailableAccessRule(String name)
        throws RemoteException {
        authorizationsession.removeAvailableAccessRule(administrator, name);
    }

    // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     *
     * @param names DOCUMENT ME!
     */
    public void removeAvailableAccessRules(Collection names)
        throws RemoteException {
        authorizationsession.removeAvailableAccessRules(administrator, names);
    }

    // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     *
     * @return DOCUMENT ME!
     */
    public Collection getAvailableAccessRules() throws RemoteException {
        return authorizationsession.getAvailableAccessRules(administrator);
    }

    // getAvailableAccessRules

    /**
     * Checks wheither an access rule exists in the database.
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean existsAvailableAccessRule(String name)
        throws RemoteException {
        return authorizationsession.existsAvailableAccessRule(administrator, name);
    }

    // existsAvailableAccessRule
    // Private fields
    private IAuthorizationSessionRemote authorizationsession;
    private AvailableResources availableresources;
    private EjbcaAuthorization authorize;
    private Admin administrator;
}
