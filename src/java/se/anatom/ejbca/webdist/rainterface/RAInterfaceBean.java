package se.anatom.ejbca.webdist.rainterface;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.hardtoken.HardTokenData;
import se.anatom.ejbca.hardtoken.IHardTokenSessionHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionRemote;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.EndEntityProfileAuthorizationProxy;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileDoesntExistsException;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;
import se.anatom.ejbca.util.query.*;
import se.anatom.ejbca.webdist.cainterface.CertificateProfileNameProxy;

import java.io.IOException;

import java.math.BigInteger;

import java.rmi.RemoteException;

import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import javax.naming.*;

import javax.servlet.http.HttpServletRequest;


/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author Philip Vendil
 * @version $Id: RAInterfaceBean.java,v 1.37 2003-06-26 11:43:26 anatom Exp $
 */
public class RAInterfaceBean {
    private static Logger log = Logger.getLogger(RAInterfaceBean.class);

    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = SecConst.MAXIMUM_QUERY_ROWCOUNT;
    public static final String[] tokentexts = {
        "TOKENSOFTBROWSERGEN", "TOKENSOFTP12", "TOKENSOFTJKS", "TOKENSOFTPEM"
    };
    public static final int[] tokenids = {
        SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS,
        SecConst.TOKEN_SOFT_PEM
    };

    /**
     * Creates new RaInterfaceBean
     */
    public RAInterfaceBean() throws IOException, NamingException, FinderException, CreateException {
        users = new UsersView();
        addedusermemory = new AddedUserMemory();
    }

    // Public methods.
    public void initialize(HttpServletRequest request)
        throws Exception {
        log.debug(">initialize()");

        if (!initialized) {
            if (request.getAttribute("javax.servlet.request.X509Certificate") != null) {
                administrator = new Admin(((X509Certificate[]) request.getAttribute(
                            "javax.servlet.request.X509Certificate"))[0]);
            } else {
                administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
            }

            // Get the UserAdminSession instance.
            jndicontext = new InitialContext();

            Object obj1 = jndicontext.lookup("UserAdminSession");
            adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    IUserAdminSessionHome.class);
            adminsession = adminsessionhome.create();

            obj1 = jndicontext.lookup("RaAdminSession");
            raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "RaAdminSession"), IRaAdminSessionHome.class);
            raadminsession = raadminsessionhome.create();
            this.profiles = new EndEntityProfileDataHandler(administrator);

            obj1 = jndicontext.lookup("CertificateStoreSession");
            certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            certificatesession = certificatesessionhome.create();

            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "AuthorizationSession"), IAuthorizationSessionHome.class);
            globalconfiguration = adminsession.loadGlobalConfiguration(administrator);
            authorizationsession = authorizationsessionhome.create();
            authorizationsession.init(globalconfiguration);

            IHardTokenSessionHome hardtokensessionhome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "HardTokenSession"), IHardTokenSessionHome.class);
            hardtokensession = hardtokensessionhome.create();

            IKeyRecoverySessionHome keyrecoverysessionhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "KeyRecoverySession"), IKeyRecoverySessionHome.class);
            keyrecoverysession = keyrecoverysessionhome.create();

            profileauthproxy = new EndEntityProfileAuthorizationProxy(authorizationsession);
            certprofilenameproxy = new CertificateProfileNameProxy(administrator);
            profilenameproxy = new EndEntityProfileNameProxy(administrator);
            initialized = true;
        } else {
            log.debug("=initialize(): already initialized");
        }

        log.debug("<initialize()");
    }

    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(UserView userdata) throws Exception {
        log.debug(">addUser()");

        if (userdata.getEndEntityProfileId() != 0) {
            adminsession.addUser(administrator, userdata.getUsername(), userdata.getPassword(),
                userdata.getSubjectDN(), userdata.getSubjectAltName(), userdata.getEmail(),
                userdata.getClearTextPassword(), userdata.getEndEntityProfileId(),
                userdata.getCertificateProfileId(), userdata.getType(), userdata.getTokenType(),
                userdata.getHardTokenIssuerId());
            addedusermemory.addUser(userdata);
        } else {
            log.debug("=addUser(): profile id not set, user not created");
        }

        log.debug("<addUser()");
    }

    /* Removes a number of users from the database.
     *
     * @param usernames an array of usernames to delete.
     * @return false if administrator wasn't authorized to delete all of given users.
     * */
    public boolean deleteUsers(String[] usernames) throws Exception {
        log.debug(">deleteUsers()");

        boolean success = true;

        for (int i = 0; i < usernames.length; i++) {
            try {
                adminsession.deleteUser(administrator, usernames[i]);
            } catch (AuthorizationDeniedException e) {
                success = false;
            }
        }

        log.debug("<deleteUsers(): " + success);

        return success;
    }

    /* Changes the status of a number of users from the database.
     *
     * @param usernames an array of usernames to change.
     * @param status gives the status to apply to users, should be one of UserDataRemote.STATUS constants.
     * @return false if administrator wasn't authorized to change all of the given users.
     * */
    public boolean setUserStatuses(String[] usernames, String status)
        throws Exception {
        log.debug(">setUserStatuses()");

        boolean success = true;
        int intstatus = 0;

        try {
            intstatus = Integer.parseInt(status);
        } catch (Exception e) {
        }

        for (int i = 0; i < usernames.length; i++) {
            try {
                adminsession.setUserStatus(administrator, usernames[i], intstatus);
            } catch (AuthorizationDeniedException e) {
                success = false;
            }
        }

        log.debug("<setUserStatuses(): " + success);

        return success;
    }

    /**
     * Revokes the given users.
     *
     * @param usernames an array of usernames to revoke.
     * @param reason reason(s) of revokation.
     *
     * @return false if administrator wasn't authorized to revoke all of the given users.
     */
    public boolean revokeUsers(String[] usernames, int reason)
        throws Exception {
        log.debug(">revokeUsers()");

        boolean success = true;

        for (int i = 0; i < usernames.length; i++) {
            try {
                adminsession.revokeUser(administrator, usernames[i], reason);
            } catch (AuthorizationDeniedException e) {
                success = false;
            }
        }

        log.debug("<revokeUsers(): " + success);

        return success;
    }

    /**
     * Revokes the  certificate with certificate serno.
     *
     * @param serno serial number of certificate to revoke.
     * @param username DOCUMENT ME!
     * @param reason reason(s) of revokation.
     *
     * @return false if administrator wasn't authorized to revoke the given certificate.
     */
    public boolean revokeCert(BigInteger serno, String username, int reason)
        throws Exception {
        log.debug(">revokeCert()");

        boolean success = true;

        try {
            adminsession.revokeCert(administrator, serno, username, reason);
        } catch (AuthorizationDeniedException e) {
            success = false;
        }

        log.debug("<revokeCert(): " + success);

        return success;
    }

    /* Changes the userdata  */
    public void changeUserData(UserView userdata) throws Exception {
        log.debug(">changeUserData()");

        int profileid = userdata.getEndEntityProfileId();
        int certificatetypeid = userdata.getCertificateProfileId();

        addedusermemory.changeUser(userdata);

        if ((userdata.getPassword() != null) && userdata.getPassword().trim().equals("")) {
            userdata.setPassword(null);
        }

        adminsession.changeUser(administrator, userdata.getUsername(), userdata.getPassword(),
            userdata.getSubjectDN(), userdata.getSubjectAltName(), userdata.getEmail(),
            userdata.getClearTextPassword(), userdata.getEndEntityProfileId(),
            userdata.getCertificateProfileId(), userdata.getType(), userdata.getTokenType(),
            userdata.getHardTokenIssuerId(), userdata.getStatus());
        log.debug("<changeUserData()");
    }

    /* Method to filter out a user by it's username */
    public UserView[] filterByUsername(String username)
        throws RemoteException, NamingException, FinderException, CreateException {
        log.debug(">filterByUserName()");

        UserAdminData[] userarray = new UserAdminData[1];
        UserAdminData user = null;

        try {
            user = adminsession.findUser(administrator, username);
        } catch (AuthorizationDeniedException e) {
        }

        if (user != null) {
            userarray[0] = user;
            users.setUsers(userarray);
        } else {
            users.setUsers((UserAdminData[]) null);
        }

        log.debug("<filterByUserName()");

        return users.getUsers(0, 1);
    }

    /* Method used to check if user exists */
    public boolean userExist(String username)
        throws RemoteException, NamingException, FinderException, CreateException {
        log.debug(">userExist(" + username + ")");

        UserAdminData user = null;

        try {
            user = adminsession.findUser(administrator, username);
        } catch (AuthorizationDeniedException e) {
        }

        boolean result = (user != null);
        log.debug("<userExist(" + username + "): " + result);

        return result;
    }

    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and page*/
    public UserView findUser(String username)
        throws RemoteException, NamingException, FinderException, CreateException,
            AuthorizationDeniedException {
        log.debug(">findUser(" + username + ")");

        UserAdminData user = adminsession.findUser(administrator, username);
        UserView userview = null;

        if (user != null) {
            userview = new UserView(user);
        }

        log.debug("<findUser(" + username + "): " + userview);

        return userview;
    }

    /* Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username)
        throws RemoteException, NamingException, FinderException, CreateException,
            AuthorizationDeniedException {
        UserView userview = null;

        UserAdminData user = adminsession.findUser(administrator, username);

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (!profileauthproxy.getEndEntityProfileAuthorization(administrator,
                        user.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.EDIT_RIGHTS, LogEntry.MODULE_ADMINWEB)) {
                throw new AuthorizationDeniedException("Not Authorized to edit user.");
            }
        }

        if (user != null) {
            userview = new UserView(user);
        }

        return userview;
    }

    /* Method to find all users in database */
    public UserView[] findAllUsers(int index, int size)
        throws RemoteException, FinderException, NamingException, NumberFormatException,
            CreateException {
        users.setUsers(adminsession.findAllUsersWithLimit(administrator));

        return users.getUsers(index, size);
    }

    /* Method to find all users in database */
    public UserView[] filterByTokenSN(String tokensn, int index, int size)
        throws Exception {
        UserView[] returnval = null;
        UserAdminData user = null;
        InitialContext ictx = new InitialContext();
        Context myenv = (Context) ictx.lookup("java:comp/env");
        boolean useprefix = false;
        String sIIN = null;

        if ((myenv.lookup("USEHARDTOKENPREFIX") != null) &&
                (myenv.lookup("ISSUERIDENTIFICATIONNUMBER") != null)) {
            useprefix = ((Boolean) myenv.lookup("USEHARDTOKENPREFIX")).booleanValue();
            sIIN = (String) myenv.lookup("ISSUERIDENTIFICATIONNUMBER");
        }

        tokensn = StringTools.stripWhitespace(tokensn);

        if (useprefix) {
            tokensn = calculateCardNumber(tokensn, sIIN);
        }

        HardTokenData token = hardtokensession.getHardToken(administrator, tokensn);

        if (token != null) {
            user = adminsession.findUser(administrator, token.getUsername());
        }

        Vector uservector = new Vector();

        if (user != null) {
            uservector.addElement(user);
        }

        users.setUsers(uservector);

        returnval = users.getUsers(index, size);

        return returnval;
    }

    /* Method that checks if a certificate serialnumber is revoked and returns the user(s), else a null value. */
    public UserView[] filterByCertificateSerialNumber(String serialnumber, int index, int size)
        throws RemoteException, FinderException, NamingException, NumberFormatException,
            CreateException {
        serialnumber = StringTools.stripWhitespace(serialnumber);

        Collection certs = certificatesession.findCertificatesBySerno(administrator,
                new BigInteger(serialnumber, 16));
        Vector uservector = new Vector();
        UserView[] returnval = null;

        if (certs != null) {
            Iterator iter = certs.iterator();

            while (iter.hasNext()) {
                UserAdminData user = null;

                try {
                    user = adminsession.findUserBySubjectDN(administrator,
                            CertTools.getSubjectDN((X509Certificate) iter.next()));
                } catch (AuthorizationDeniedException e) {
                    user = null;
                }

                if (user != null) {
                    uservector.addElement(user);
                }
            }

            users.setUsers(uservector);

            returnval = users.getUsers(index, size);
        }

        return returnval;
    }

    /* Method that lists all users with certificate's that expires within given days. */
    public UserView[] filterByExpiringCertificates(String days, int index, int size)
        throws RemoteException, FinderException, NumberFormatException, NamingException,
            CreateException {
        Vector uservector = new Vector();
        UserView[] returnval = null;

        long d = Long.parseLong(days);
        Date finddate = new Date();
        long millis = (d * 86400000); // One day in milliseconds.
        finddate.setTime(finddate.getTime() + (long) millis);

        Collection usernames = certificatesession.findCertificatesByExpireTimeWithLimit(administrator,
                finddate);

        if (!usernames.isEmpty()) {
            Iterator i = usernames.iterator();

            while (i.hasNext() && (uservector.size() <= (MAXIMUM_QUERY_ROWCOUNT + 1))) {
                UserAdminData user = null;

                try {
                    user = adminsession.findUser(administrator, (String) i.next());
                } catch (AuthorizationDeniedException e) {
                    user = null;
                }

                if (user != null) {
                    uservector.addElement(user);
                }
            }

            users.setUsers(uservector);

            returnval = users.getUsers(index, size);
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param query DOCUMENT ME!
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public UserView[] filterByQuery(Query query, int index, int size)
        throws Exception {
        Collection uservector = (Collection) adminsession.query(administrator, query);
        users.setUsers(uservector);

        return users.getUsers(index, size);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getResultSize() {
        return users.size();
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public boolean isAuthorizedToViewUserHistory(String username)
        throws Exception {
        UserAdminData user = adminsession.findUser(administrator, username);

        return profileauthproxy.getEndEntityProfileAuthorization(administrator,
            user.getEndEntityProfileId(), EndEntityProfileAuthorizationProxy.HISTORY_RIGHTS,
            LogEntry.MODULE_ADMINWEB);
    }

    /* Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder) {
        users.sortBy(sortby, sortorder);
    }

    /* Method to return the users between index and size, if userdata is smaller than size, a smaller array is returned. */
    public UserView[] getUsers(int index, int size) {
        return users.getUsers(index, size);
    }

    /* Method that clears the userview memory. */
    public void clearUsers() {
        users.clear();
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean nextButton(int index, int size) {
        return (index + size) < users.size();
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean previousButton(int index, int size) {
        return index > 0;
    }

    // Method dealing with added user memory.

    /**
     * A method to get the last added users in adduser.jsp.
     *
     * @see se.anatom.ejbca.webdist.rainterface.AddedUserMemory
     */
    public UserView[] getAddedUsers(int size) {
        return addedusermemory.getUsers(size);
    }

    // Methods dealing with profiles.
    public String[] getEndEntityProfileNames() throws RemoteException {
        return profiles.getEndEntityProfileNames();
    }

    /**
     * Returns the profile name from id proxied
     *
     * @param profileid DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getEndEntityProfileName(int profileid)
        throws RemoteException {
        return profilenameproxy.getEndEntityProfileName(profileid);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String[] getCreateAuthorizedEndEntityProfileNames()
        throws RemoteException {
        Vector result = new Vector();
        String[] profilenames = profiles.getEndEntityProfileNames();
        String[] dummy = {  };

        for (int i = 0; i < profilenames.length; i++) {
            if (profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator,
                        profiles.getEndEntityProfileId(profilenames[i]),
                        EndEntityProfileAuthorizationProxy.CREATE_RIGHTS)) {
                result.add(profilenames[i]);
            }
        }

        return (String[]) result.toArray(dummy);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String[] getEditAuthorizedEndEntityProfileNames()
        throws RemoteException {
        Vector result = new Vector();
        String[] profilenames = profiles.getEndEntityProfileNames();
        String[] dummy = {  };

        for (int i = 0; i < profilenames.length; i++) {
            if (profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator,
                        profiles.getEndEntityProfileId(profilenames[i]),
                        EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)) {
                result.add(profilenames[i]);
            }
        }

        return (String[]) result.toArray(dummy);
    }

    /**
     * DOCUMENT ME!
     *
     * @param profilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getEndEntityProfileId(String profilename)
        throws RemoteException {
        return profiles.getEndEntityProfileId(profilename);
    }

    /* Returns profiles as a EndEntityProfiles object */
    public EndEntityProfileDataHandler getEndEntityProfileDataHandler() {
        return profiles;
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(String name)
        throws RemoteException {
        return profiles.getEndEntityProfile(name);
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(int id)
        throws RemoteException {
        return profiles.getEndEntityProfile(id);
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     *
     * @throws EndEntityProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void addEndEntityProfile(String name)
        throws EndEntityProfileExistsException, RemoteException {
        profiles.addEndEntityProfile(name, new EndEntityProfile());
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @throws EndEntityProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void addEndEntityProfile(String name, EndEntityProfile profile)
        throws EndEntityProfileExistsException, RemoteException {
        profiles.addEndEntityProfile(name, profile);
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @throws EndEntityProfileDoesntExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void changeEndEntityProfile(String name, EndEntityProfile profile)
        throws EndEntityProfileDoesntExistsException, RemoteException {
        profiles.changeEndEntityProfile(name, profile);
    }

    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeEndEntityProfile(String name)
        throws RemoteException {
        boolean profileused = false;
        int profileid = raadminsession.getEndEntityProfileId(administrator, name);

        // Check if any users or authorization rule use the profile.
        profileused = adminsession.checkForEndEntityProfileId(administrator, profileid) ||
            authorizationsession.existsEndEntityProfileInRules(administrator, profileid);

        if (!profileused) {
            profiles.removeEndEntityProfile(name);
        }

        return !profileused;
    }

    /**
     * DOCUMENT ME!
     *
     * @param oldname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     *
     * @throws EndEntityProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void renameEndEntityProfile(String oldname, String newname)
        throws EndEntityProfileExistsException, RemoteException {
        profiles.renameEndEntityProfile(oldname, newname);
    }

    /**
     * DOCUMENT ME!
     *
     * @param originalname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     *
     * @throws EndEntityProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void cloneEndEntityProfile(String originalname, String newname)
        throws EndEntityProfileExistsException, RemoteException {
        profiles.cloneEndEntityProfile(originalname, newname);
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     */
    public void loadCertificates(String username)
        throws RemoteException, NamingException, CreateException, AuthorizationDeniedException,
            FinderException {
        Collection certs = certificatesession.findCertificatesByUsername(administrator, username);

        UserAdminData user = adminsession.findUser(administrator, username);

        if (!certs.isEmpty()) {
            Iterator j = certs.iterator();
            certificates = new CertificateView[certs.size()];

            for (int i = 0; i < certificates.length; i++) {
                RevokedInfoView revokedinfo = null;
                X509Certificate cert = (X509Certificate) j.next();
                RevokedCertInfo revinfo = certificatesession.isRevoked(administrator,
                        CertTools.getIssuerDN(cert), cert.getSerialNumber());

                if (revinfo != null) {
                    revokedinfo = new RevokedInfoView(revinfo);
                }

                certificates[i] = new CertificateView(cert, revokedinfo, username);
            }
        } else {
            certificates = null;
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     */
    public void loadTokenCertificates(String tokensn, String username)
        throws RemoteException, NamingException, CreateException, AuthorizationDeniedException,
            FinderException {
        Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);

        UserAdminData user = adminsession.findUser(administrator, username);

        if (!certs.isEmpty()) {
            Iterator j = certs.iterator();
            certificates = new CertificateView[certs.size()];

            for (int i = 0; i < certificates.length; i++) {
                RevokedInfoView revokedinfo = null;
                X509Certificate cert = (X509Certificate) j.next();
                RevokedCertInfo revinfo = certificatesession.isRevoked(administrator,
                        CertTools.getIssuerDN(cert), cert.getSerialNumber());

                if (revinfo != null) {
                    revokedinfo = new RevokedInfoView(revinfo);
                }

                certificates[i] = new CertificateView(cert, revokedinfo, username);
            }
        } else {
            certificates = null;
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param reason DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     */
    public boolean revokeTokenCertificates(String tokensn, String username, int reason)
        throws RemoteException, NamingException, CreateException, AuthorizationDeniedException,
            FinderException {
        boolean success = true;

        Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);
        Iterator i = certs.iterator();

        try {
            while (i.hasNext()) {
                adminsession.revokeCert(administrator,
                    ((X509Certificate) i.next()).getSerialNumber(), username, reason);
            }
        } catch (AuthorizationDeniedException e) {
            success = false;
        }

        return success;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     */
    public boolean isAllTokenCertificatesRevoked(String tokensn, String username)
        throws RemoteException, NamingException, CreateException, AuthorizationDeniedException,
            FinderException {
        Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);

        UserAdminData user = adminsession.findUser(administrator, username);
        boolean allrevoked = true;

        if (!certs.isEmpty()) {
            Iterator j = certs.iterator();

            while (j.hasNext()) {
                X509Certificate cert = (X509Certificate) j.next();
                RevokedCertInfo revinfo = certificatesession.isRevoked(administrator,
                        CertTools.getIssuerDN(cert), cert.getSerialNumber());

                if (revinfo == null) {
                    allrevoked = false;
                }
            }
        }

        return allrevoked;
    }

    /**
     * DOCUMENT ME!
     *
     * @param cacerts DOCUMENT ME!
     */
    public void loadCACertificates(CertificateView[] cacerts) {
        certificates = cacerts;
    }

    /**
     * DOCUMENT ME!
     *
     * @param serno DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     */
    public void loadCertificates(BigInteger serno)
        throws RemoteException, NamingException, CreateException, AuthorizationDeniedException,
            FinderException {
        Collection certs = certificatesession.findCertificatesBySerno(administrator, serno);
        String username = certificatesession.findUsernameByCertSerno(administrator, serno);

        UserAdminData user = adminsession.findUser(administrator, username);

        if (!certs.isEmpty()) {
            Iterator j = certs.iterator();
            certificates = new CertificateView[certs.size()];

            for (int i = 0; i < certificates.length; i++) {
                RevokedInfoView revokedinfo = null;
                X509Certificate cert = (X509Certificate) j.next();
                RevokedCertInfo revinfo = certificatesession.isRevoked(administrator,
                        CertTools.getIssuerDN(cert), cert.getSerialNumber());

                if (revinfo != null) {
                    revokedinfo = new RevokedInfoView(revinfo);
                }

                certificates[i] = new CertificateView(cert, revokedinfo, username);
            }
        } else {
            certificates = null;
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfCertificates() {
        int returnval = 0;

        if (certificates != null) {
            returnval = certificates.length;
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateView getCertificate(int index) {
        CertificateView returnval = null;

        if (certificates != null) {
            returnval = certificates[index];
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param profileid DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public boolean authorizedToEditUser(int profileid)
        throws RemoteException {
        return profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator, profileid,
            EndEntityProfileAuthorizationProxy.EDIT_RIGHTS);
    }

    /**
     * DOCUMENT ME!
     *
     * @param profileid DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public boolean authorizedToViewHistory(int profileid)
        throws RemoteException {
        return profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator, profileid,
            EndEntityProfileAuthorizationProxy.HISTORY_RIGHTS);
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public boolean authorizedToViewHardToken(String username)
        throws Exception {
        int profileid = adminsession.findUser(administrator, username).getEndEntityProfileId();

        return profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator, profileid,
            EndEntityProfileAuthorizationProxy.HARDTOKEN_VIEW_RIGHTS);
    }

    /**
     * DOCUMENT ME!
     *
     * @param profileid DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public boolean authorizedToViewHardToken(int profileid)
        throws Exception {
        return profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator, profileid,
            EndEntityProfileAuthorizationProxy.HARDTOKEN_VIEW_RIGHTS);
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     * @throws AuthorizationDeniedException DOCUMENT ME!
     */
    public boolean authorizedToRevokeCert(String username)
        throws FinderException, RemoteException, AuthorizationDeniedException {
        boolean returnval = false;
        int profileid = (adminsession.findUser(administrator, username)).getEndEntityProfileId();

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            returnval = profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator,
                    profileid, EndEntityProfileAuthorizationProxy.REVOKE_RIGHTS);
        } else {
            returnval = true;
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatedata DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public boolean keyRecoveryPossible(CertificateView certificatedata)
        throws Exception {
        boolean returnval = true;

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            int profileid = adminsession.findUser(administrator, certificatedata.getUsername())
                                        .getEndEntityProfileId();
            returnval = profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator,
                    profileid, EndEntityProfileAuthorizationProxy.KEYRECOVERY_RIGHTS);
        }

        return returnval &&
        keyrecoverysession.existsKeys(administrator, certificatedata.getCertificate()) &&
        !keyrecoverysession.isUserMarked(administrator, certificatedata.getUsername());
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatedata DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void markForRecovery(CertificateView certificatedata)
        throws Exception {
        boolean authorized = true;

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            int profileid = adminsession.findUser(administrator, certificatedata.getUsername())
                                        .getEndEntityProfileId();
            authorized = profileauthproxy.getEndEntityProfileAuthorizationNoLog(administrator,
                    profileid, EndEntityProfileAuthorizationProxy.KEYRECOVERY_RIGHTS);
        }

        if (authorized) {
            keyrecoverysession.markAsRecoverable(administrator, certificatedata.getCertificate());
            adminsession.setUserStatus(administrator, certificatedata.getUsername(),
                UserDataRemote.STATUS_KEYRECOVERY);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String[] getCertificateProfileNames() throws RemoteException {
        String[] dummy = { "" };
        Collection certprofilenames = certificatesession.getCertificateProfileNames(administrator);

        if (certprofilenames == null) {
            return new String[0];
        } else {
            return (String[]) certprofilenames.toArray(dummy);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getCertificateProfileId(String certificateprofilename)
        throws RemoteException {
        return certificatesession.getCertificateProfileId(administrator, certificateprofilename);
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofileid DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getCertificateProfileName(int certificateprofileid)
        throws RemoteException {
        return certprofilenameproxy.getCertificateProfileName(certificateprofileid);
    }

    /**
     * DOCUMENT ME!
     *
     * @param parameter DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getEndEntityParameter(String parameter) {
        if (parameter == null) {
            return false;
        }

        return parameter.equals(EndEntityProfile.TRUE);
    }

    // Private methods.
    private String calculateCardNumber(String tokensn, String sIIN) {
        while ((tokensn.length() + sIIN.length()) < 18) {
            tokensn = "0" + tokensn;
        }

        final int lengthByte = tokensn.length() + sIIN.length() + 1;
        final long divider = pow(10, tokensn.length());
        final long number = (Long.parseLong(sIIN) * divider) + Long.parseLong(tokensn);
        final int chsum;

        {
            int sum = 0;

            for (int i = 0; (i + 1) < lengthByte; i++) {
                int digit = (int) ((number / pow(10, i)) % 10);

                if ((i % 2) == 0) {
                    digit *= 2;
                    sum += ((digit / 10) + (digit % 10));
                } else {
                    sum += digit;
                }
            }

            chsum = (10 - (sum % 10)) % 10;
        }

        return ("" + lengthByte + number + chsum + (((lengthByte % 2) == 1) ? "0" : ""));
    }

    private long pow(int x, int y) {
        long result = 1;

        for (int i = 0; i < y; i++) {
            result *= x;
        }

        return result;
    }

    // Private fields.
    private EndEntityProfileDataHandler profiles;
    private InitialContext jndicontext;
    private IUserAdminSessionRemote adminsession;
    private IUserAdminSessionHome adminsessionhome;
    private ICertificateStoreSessionRemote certificatesession;
    private ICertificateStoreSessionHome certificatesessionhome;
    private IRaAdminSessionHome raadminsessionhome;
    private IRaAdminSessionRemote raadminsession;
    private IAuthorizationSessionRemote authorizationsession;
    private IHardTokenSessionRemote hardtokensession;
    private IKeyRecoverySessionRemote keyrecoverysession;
    private UsersView users;
    private CertificateView[] certificates;
    private AddedUserMemory addedusermemory;
    private Admin administrator;
    private EndEntityProfileAuthorizationProxy profileauthproxy;
    private CertificateProfileNameProxy certprofilenameproxy;
    private EndEntityProfileNameProxy profilenameproxy;
    private GlobalConfiguration globalconfiguration;
    private boolean initialized = false;
}
