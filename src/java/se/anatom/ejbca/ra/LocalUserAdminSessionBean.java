package se.anatom.ejbca.ra;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.IPublisherSessionHome;
import se.anatom.ejbca.ca.store.IPublisherSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.EndEntityProfileAuthorizationProxy;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ra.exception.NotFoundException;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;
import se.anatom.ejbca.util.query.*;

import java.math.BigInteger;

import java.rmi.*;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.sql.*;

import java.util.*;

import javax.ejb.*;

import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import javax.naming.*;

import javax.sql.DataSource;


/**
 * Administrates users in the database using UserData Entity Bean. Uses JNDI name for datasource as
 * defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalUserAdminSessionBean.java,v 1.57 2003-06-26 11:43:24 anatom Exp $
 */
public class LocalUserAdminSessionBean extends BaseSessionBean {
    /** The home interface of  GlobalConfiguration entity bean */
    private GlobalConfigurationDataLocalHome globalconfigurationhome = null;

    /** Var containing the global configuration. */
    private GlobalConfiguration globalconfiguration;

    /** The local interface of RaAdmin Session Bean. */
    private IRaAdminSessionLocal raadminsession;

    /** The remote interface of the certificate store session bean */
    private ICertificateStoreSessionRemote certificatesession;

    /** A vector of publishers home interfaces where certs and CRLs are stored */
    private ArrayList publishers = null;

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;
    private UserDataLocalHome home = null;

    /** Columns in the database used in select */
    private final String USERDATA_COL = "username, subjectDN, subjectAltName, subjectEmail, status, type, clearpassword, timeCreated, timeModified, endEntityprofileId, certificateProfileId, tokenType, hardTokenIssuerId";

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** Class used to create notification messages. */
    private NotificationCreator notificationcreator;

    /** Var optimizing authorization lookups. */
    private EndEntityProfileAuthorizationProxy profileauthproxy;

    /**
     * Default create for SessionBean.
     *
     * @throws CreateException if bean instance can't be created
     *
     * @see se.anatom.ejbca.log.Admin
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");

        try {
            home = (UserDataLocalHome) lookup("java:comp/env/ejb/UserDataLocal",
                    UserDataLocalHome.class);
            globalconfigurationhome = (GlobalConfigurationDataLocalHome) lookup("java:comp/env/ejb/GlobalConfigurationDataLocal",
                    GlobalConfigurationDataLocalHome.class);
            dataSource = (String) lookup("java:comp/env/DataSource", java.lang.String.class);
            debug("DataSource=" + dataSource);

            this.globalconfiguration = loadGlobalConfiguration(new Admin(Admin.TYPE_INTERNALUSER));

            ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",
                    ILogSessionHome.class);
            logsession = logsessionhome.create();

            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal",
                    IAuthorizationSessionLocalHome.class);
            IAuthorizationSessionLocal authorizationsession = authorizationsessionhome.create();
            authorizationsession.init(globalconfiguration);

            IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) lookup("java:comp/env/ejb/RaAdminSessionLocal",
                    IRaAdminSessionLocalHome.class);
            raadminsession = raadminsessionhome.create();

            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) lookup("java:comp/env/ejb/CertificateStoreSession",
                    ICertificateStoreSessionHome.class);
            certificatesession = certificatesessionhome.create();

            // Init the publisher session beans
            int i = 1;
            publishers = new ArrayList();

            try {
                while (true) {
                    String jndiName = "java:comp/env/ejb/PublisherSession" + i;
                    IPublisherSessionHome pubHome = (IPublisherSessionHome) lookup(jndiName);
                    publishers.add(pubHome);
                    debug("Added publisher class '" + pubHome.getClass().getName() + "'");
                    i++;
                }
            } catch (EJBException e) {
                // We could not find this publisher
                debug("Failed to find publisher at index '" + i + "', no more publishers.");
            }

            profileauthproxy = new EndEntityProfileAuthorizationProxy(authorizationsession);

            notificationcreator = new NotificationCreator((String) lookup("java:comp/env/sender",
                        java.lang.String.class),
                    (String) lookup("java:comp/env/subject", java.lang.String.class),
                    (String) lookup("java:comp/env/message", java.lang.String.class));
        } catch (Exception e) {
            error("Error creating session bean:", e);
            throw new EJBException(e);
        }
    }

    /**
     * Gets connection to Datasource used for manual SQL searches
     *
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource) getInitialContext().lookup(dataSource);

        return ds.getConnection();
    }
     //getConnection

    /**
     * Implements IUserAdminSession::addUser. Implements a mechanism that uses UserDataEntity Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     * @param subjectdn DOCUMENT ME!
     * @param subjectaltname DOCUMENT ME!
     * @param email DOCUMENT ME!
     * @param clearpwd DOCUMENT ME!
     * @param endentityprofileid DOCUMENT ME!
     * @param certificateprofileid DOCUMENT ME!
     * @param type DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param hardwaretokenissuerid DOCUMENT ME!
     */
    public void addUser(Admin admin, String username, String password, String subjectdn,
        String subjectaltname, String email, boolean clearpwd, int endentityprofileid,
        int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid)
        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException {
        // String used in SQL so strip it
        String dn = StringTools.strip(subjectdn);
        debug(">addUser(" + username + ", password, " + dn + ", " + email + ")");

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, endentityprofileid);

            try {
                profile.doesUserFullfillEndEntityProfile(username, password, dn, subjectaltname,
                    email, certificateprofileid, clearpwd,
                    (type & SecConst.USER_ADMINISTRATOR) != 0,
                    (type & SecConst.USER_KEYRECOVERABLE) != 0,
                    (type & SecConst.USER_SENDNOTIFICATION) != 0, tokentype, hardwaretokenissuerid);
            } catch (UserDoesntFullfillEndEntityProfile udfp) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_ADDEDENDENTITY,
                    "Userdata didn'nt fullfill end entity profile. " + udfp.getMessage());
                throw new UserDoesntFullfillEndEntityProfile(udfp.getMessage());
            }

            // Check if administrator is authorized to add user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin, endentityprofileid,
                        EndEntityProfileAuthorizationProxy.CREATE_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_ADDEDENDENTITY, "Administrator not authorized");
                throw new AuthorizationDeniedException(
                    "Administrator not authorized to create user.");
            }
        }

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = null;
            data1 = home.create(pk.toString(), password, dn);

            if (subjectaltname != null) {
                data1.setSubjectAltName(subjectaltname);
            }

            if (email != null) {
                data1.setSubjectEmail(email);
            }

            data1.setType(type);
            data1.setEndEntityProfileId(endentityprofileid);
            data1.setCertificateProfileId(certificateprofileid);
            data1.setTokenType(tokentype);
            data1.setHardTokenIssuerId(hardwaretokenissuerid);

            if (clearpwd) {
                try {
                    if (password == null) {
                        data1.setClearPassword("");
                    } else {
                        data1.setOpenPassword(password);
                    }
                } catch (java.security.NoSuchAlgorithmException nsae) {
                    debug("NoSuchAlgorithmException while setting password for user " + username);
                    throw new EJBException(nsae);
                }
            }

            if ((type & SecConst.USER_SENDNOTIFICATION) != 0) {
                sendNotification(admin, username, password, dn, subjectaltname, email);
            }

            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_INFO_ADDEDENDENTITY, "");
        } catch (Exception e) {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_ERROR_ADDEDENDENTITY, "");
            error("AddUser:", e);
            throw new EJBException(e);
        }

        debug("<addUser(" + username + ", password, " + dn + ", " + email + ")");
    }
     // addUser

    /**
     * Implements IUserAdminSession::changeUser. Implements a mechanism that uses UserDataEntity
     * Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     * @param subjectdn DOCUMENT ME!
     * @param subjectaltname DOCUMENT ME!
     * @param email DOCUMENT ME!
     * @param clearpwd DOCUMENT ME!
     * @param endentityprofileid DOCUMENT ME!
     * @param certificateprofileid DOCUMENT ME!
     * @param type DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param hardwaretokenissuerid DOCUMENT ME!
     * @param status DOCUMENT ME!
     */
    public void changeUser(Admin admin, String username, String password, String subjectdn,
        String subjectaltname, String email, boolean clearpwd, int endentityprofileid,
        int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid, int status)
        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException {
        // String used in SQL so strip it
        String dn = StringTools.strip(subjectdn);
        boolean statuschanged = false;
        debug(">changeUser(" + username + ", " + dn + ", " + email + ")");

        int oldstatus;

        // Check if user fulfills it's profile.
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, endentityprofileid);

            try {
                profile.doesUserFullfillEndEntityProfileWithoutPassword(username, dn,
                    subjectaltname, email, certificateprofileid,
                    (type & SecConst.USER_ADMINISTRATOR) != 0,
                    (type & SecConst.USER_KEYRECOVERABLE) != 0,
                    (type & SecConst.USER_SENDNOTIFICATION) != 0, tokentype, hardwaretokenissuerid);
            } catch (UserDoesntFullfillEndEntityProfile udfp) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                    "Userdata didn'nt fullfill end entity profile. + " + udfp.getMessage());
                throw new UserDoesntFullfillEndEntityProfile(udfp.getMessage());
            }

            // Check if administrator is authorized to edit user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin, endentityprofileid,
                        EndEntityProfileAuthorizationProxy.EDIT_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY, "Administrator not authorized");
                throw new AuthorizationDeniedException("Administrator not authorized to edit user.");
            }
        }

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);

            if (password != null) {
                if (clearpwd) {
                    setClearTextPassword(admin, username, password);
                } else {
                    setPassword(admin, username, password);
                }
            }

            data1.setDN(dn);

            if (subjectaltname != null) {
                data1.setSubjectAltName(subjectaltname);
            }

            if (email != null) {
                data1.setSubjectEmail(email);
            }

            data1.setType(type);
            data1.setEndEntityProfileId(endentityprofileid);
            data1.setCertificateProfileId(certificateprofileid);
            data1.setTokenType(tokentype);
            data1.setHardTokenIssuerId(hardwaretokenissuerid);
            oldstatus = data1.getStatus();
            statuschanged = status != oldstatus;
            data1.setStatus(status);

            data1.setTimeModified((new java.util.Date()).getTime());

            if (((type & SecConst.USER_SENDNOTIFICATION) != 0) && statuschanged &&
                    ((status == UserDataLocal.STATUS_NEW) ||
                    (status == UserDataLocal.STATUS_KEYRECOVERY))) {
                sendNotification(admin, username, password, dn, subjectaltname, email);
            }

            if (statuschanged) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_INFO_CHANGEDENDENTITY, "New status: " + status);
            } else {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_INFO_CHANGEDENDENTITY, "");
            }
        } catch (Exception e) {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_ERROR_CHANGEDENDENTITY, "");
            error("ChangeUser:", e);
            throw new EJBException(e);
        }

        debug("<changeUser(" + username + ", password, " + dn + ", " + email + ")");
    }
     // changeUser

    /**
     * Implements IUserAdminSession::deleteUser. Implements a mechanism that uses UserData Entity
     * Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     */
    public void deleteUser(Admin admin, String username)
        throws AuthorizationDeniedException, NotFoundException, FinderException, RemoveException,
            RemoteException {
        debug(">deleteUser(" + username + ")");

        // Check if administrator is authorized to delete user.
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            try {
                UserDataPK pk = new UserDataPK(username);
                UserDataLocal data1 = home.findByPrimaryKey(pk);

                if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                            data1.getEndEntityProfileId(),
                            EndEntityProfileAuthorizationProxy.DELETE_RIGHTS, LogEntry.MODULE_RA)) {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                        LogEntry.EVENT_ERROR_DELETEENDENTITY, "Administrator not authorized");
                    throw new AuthorizationDeniedException(
                        "Administrator not authorized to delete user.");
                }
            } catch (FinderException e) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_DELETEENDENTITY, "Couldn't find username in database");
                throw e;
            }
        }

        try {
            UserDataPK pk = new UserDataPK(username);
            home.remove(pk);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_INFO_DELETEDENDENTITY, "");
        } catch (EJBException e) {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_ERROR_DELETEENDENTITY, "Couldn't find username in database");
            throw new NotFoundException("Couldn't find '" + username + "' in database");
        }

        debug("<deleteUser(" + username + ")");
    }
     // deleteUser

    /**
     * Implements IUserAdminSession::setUserStatus. Implements a mechanism that uses UserData
     * Entity Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param status DOCUMENT ME!
     */
    public void setUserStatus(Admin admin, String username, int status)
        throws AuthorizationDeniedException, FinderException, RemoteException {
        debug(">setUserStatus(" + username + ", " + status + ")");

        // Check if administrator is authorized to edit user.
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            try {
                UserDataPK pk = new UserDataPK(username);
                UserDataLocal data1 = home.findByPrimaryKey(pk);

                if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                            data1.getEndEntityProfileId(),
                            EndEntityProfileAuthorizationProxy.EDIT_RIGHTS, LogEntry.MODULE_RA)) {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                        LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                        "Administrator not authorized to change status");
                    throw new AuthorizationDeniedException(
                        "Administrator not authorized to edit user.");
                }
            } catch (FinderException e) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY, "Couldn't find username in database.");
                throw e;
            }
        }

        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        data.setStatus(status);
        data.setTimeModified((new java.util.Date()).getTime());
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
            LogEntry.EVENT_INFO_CHANGEDENDENTITY, ("New status : " + status));
        debug("<setUserStatus(" + username + ", " + status + ")");
    }
     // setUserStatus

    /**
     * Implements IUserAdminSession::setPassword. Implements a mechanism that uses UserData Entity
     * Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     */
    public void setPassword(Admin admin, String username, String password)
        throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException,
            RemoteException {
        debug(">setPassword(" + username + ", hiddenpwd)");

        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            EndEntityProfile profile = raadminsession.getEndEntityProfile(admin,
                    data.getEndEntityProfileId());

            boolean fullfillsprofile = true;
            System.out.println("Set Password" + password);

            if (!profile.isModifyable(EndEntityProfile.PASSWORD, 0)) {
                if (!password.equals(profile.getValue(EndEntityProfile.PASSWORD, 0))) {
                    ;
                }

                fullfillsprofile = false;
            } else if (profile.isRequired(EndEntityProfile.PASSWORD, 0)) {
                if ((password == null) || password.trim().equals("")) {
                    fullfillsprofile = false;
                }
            }

            if (!fullfillsprofile) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                    "Password didn't fulfill end entity profile.");
                throw new UserDoesntFullfillEndEntityProfile(
                    "Password didn't fulfill end entity profile.");
            }

            // Check if administrator is authorized to edit user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.EDIT_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                    "Administrator isn't authorized to change password.");
                throw new AuthorizationDeniedException("Administrator not authorized to edit user.");
            }
        }

        try {
            data.setPassword(password);
            data.setTimeModified((new java.util.Date()).getTime());
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_INFO_CHANGEDENDENTITY, "Password changed.");
        } catch (java.security.NoSuchAlgorithmException nsae) {
            debug("NoSuchAlgorithmException while setting password for user " + username);
            throw new EJBException(nsae);
        }

        debug("<setPassword(" + username + ", hiddenpwd)");
    }
     // setPassword

    /**
     * Implements IUserAdminSession::setClearTextPassword. Implements a mechanism that uses
     * UserData Entity Bean.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     */
    public void setClearTextPassword(Admin admin, String username, String password)
        throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException,
            RemoteException {
        debug(">setClearTextPassword(" + username + ", hiddenpwd)");

        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            EndEntityProfile profile = raadminsession.getEndEntityProfile(admin,
                    data.getEndEntityProfileId());

            if (profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0) &&
                    profile.getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0).equals(EndEntityProfile.FALSE)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                    "Clearpassword didn't fullfill end entity profile.");
                throw new UserDoesntFullfillEndEntityProfile(
                    "Clearpassword didn't fullfill end entity profile.");
            }

            // Check if administrator is authorized to edit user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.EDIT_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CHANGEDENDENTITY,
                    "Administrator isn't authorized to change clearpassword.");
                throw new AuthorizationDeniedException("Administrator not authorized to edit user.");
            }
        }

        try {
            if (password == null) {
                data.setClearPassword("");
                data.setTimeModified((new java.util.Date()).getTime());
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_INFO_CHANGEDENDENTITY, "Clearpassword changed.");
            } else {
                data.setOpenPassword(password);
                data.setTimeModified((new java.util.Date()).getTime());
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_INFO_CHANGEDENDENTITY, "Clearpassword changed.");
            }
        } catch (java.security.NoSuchAlgorithmException nsae) {
            debug("NoSuchAlgorithmException while setting password for user " + username);
            throw new EJBException(nsae);
        }

        debug("<setClearTextPassword(" + username + ", hiddenpwd)");
    }
     // setClearTextPassword

    /**
     * Method that revokes a user.
     *
     * @param username the username to revoke.
     * @param username DOCUMENT ME!
     * @param reason DOCUMENT ME!
     */
    public void revokeUser(Admin admin, String username, int reason)
        throws AuthorizationDeniedException, FinderException, RemoteException {
        debug(">revokeUser(" + username + ")");

        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;

        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            throw new EJBException(oe);
        }

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.REVOKE_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_REVOKEDENDENTITY, "Administrator not authorized");
                throw new AuthorizationDeniedException("Not authorized to revoke user : " +
                    username + ".");
            }
        }

        setUserStatus(admin, username, UserDataRemote.STATUS_REVOKED);
        certificatesession.setRevokeStatus(admin, username, reason);
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
            LogEntry.EVENT_INFO_REVOKEDENDENTITY, "");
        debug("<revokeUser()");
    }
     // revokeUser

    /**
     * Method that revokes a certificate.
     *
     * @param certserno the serno of certificate to revoke.
     * @param username the username to revoke.
     * @param reason the reason of revokation.
     * @param reason DOCUMENT ME!
     */
    public void revokeCert(Admin admin, BigInteger certserno, String username, int reason)
        throws AuthorizationDeniedException, FinderException, RemoteException {
        debug(">revokeCert(" + certserno + ", " + username + ")");

        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;

        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            throw new EJBException(oe);
        }

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.REVOKE_RIGHTS, LogEntry.MODULE_RA)) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_REVOKEDENDENTITY, "Administrator not authorized");
                throw new AuthorizationDeniedException("Not authorized to revoke user : " +
                    username + ".");
            }
        }

        certificatesession.setRevokeStatus(admin, certserno, reason);

        // Revoke certificate in publishers
        if (publishers.size() > 0) {
            Collection certs = certificatesession.findCertificatesBySubject(admin,
                    data.getSubjectDN());
            Iterator iter = certs.iterator();

            while (iter.hasNext()) {
                Certificate cert = (Certificate) iter.next();

                if (cert instanceof X509Certificate) {
                    X509Certificate x509cert = (X509Certificate) cert;

                    if (x509cert.getSerialNumber().compareTo(certserno) == 0) {
                        for (int i = 0; i < publishers.size(); i++) {
                            try {
                                IPublisherSessionHome pubHome = (IPublisherSessionHome) publishers.get(i);
                                IPublisherSessionRemote pub = pubHome.create();
                                pub.revokeCertificate(admin, cert, reason);
                            } catch (CreateException e) {
                                log.debug("Error creating publisher session: ", e);
                            }
                        }
                    }
                }
            }
        }
         // if (publishers.size() > 0)

        if (certificatesession.checkIfAllRevoked(admin, username)) {
            setUserStatus(admin, username, UserDataRemote.STATUS_REVOKED);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_INFO_REVOKEDENDENTITY, "");
        }

        debug("<revokeCert()");
    }
     // revokeUser

    /**
     * Implements IUserAdminSession::findUser.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public UserAdminData findUser(Admin admin, String username)
        throws FinderException, AuthorizationDeniedException, RemoteException {
        debug(">findUser(" + username + ")");

        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;

        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            return null;
        }

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to view user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                throw new AuthorizationDeniedException("Administrator not authorized to view user.");
            }
        }

        UserAdminData ret = new UserAdminData(data.getUsername(), data.getSubjectDN(),
                data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus(), data.getType(),
                data.getEndEntityProfileId(), data.getCertificateProfileId(),
                new java.util.Date(data.getTimeCreated()),
                new java.util.Date(data.getTimeModified()), data.getTokenType(),
                data.getHardTokenIssuerId());
        ret.setPassword(data.getClearPassword());
        debug("<findUser(" + username + ")");

        return ret;
    }
     // findUser

    /**
     * Implements IUserAdminSession::findUserBySubjectDN.
     *
     * @param admin DOCUMENT ME!
     * @param subjectdn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public UserAdminData findUserBySubjectDN(Admin admin, String subjectdn)
        throws AuthorizationDeniedException, RemoteException {
        debug(">findUserBySubjectDN(" + subjectdn + ")");

        String bcdn = CertTools.stringToBCDNString(subjectdn);

        // String used in SQL so strip it
        String dn = StringTools.strip(bcdn);
        debug("Looking for users with subjectdn: " + dn);

        UserAdminData returnval = null;

        UserDataLocal data = null;

        try {
            data = home.findBySubjectDN(dn);
        } catch (FinderException e) {
            log.debug("Cannot find user with DN='" + dn + "'");
        }

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to view user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                throw new AuthorizationDeniedException("Administrator not authorized to view user.");
            }
        }

        if (data != null) {
            returnval = new UserAdminData(data.getUsername(), data.getSubjectDN(),
                    data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus(),
                    data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId(),
                    new java.util.Date(data.getTimeCreated()),
                    new java.util.Date(data.getTimeModified()), data.getTokenType(),
                    data.getHardTokenIssuerId());

            returnval.setPassword(data.getClearPassword());
        }

        debug("<findUserBySubjectDN(" + subjectdn + ")");

        return returnval;
    }
     // findUserBySubjectDN

    /**
     * Implements IUserAdminSession::findUserBySubjectDN.
     *
     * @param admin DOCUMENT ME!
     * @param email DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public UserAdminData findUserByEmail(Admin admin, String email)
        throws AuthorizationDeniedException, RemoteException {
        debug(">findUserByEmail(" + email + ")");
        debug("Looking for user with email: " + email);

        UserAdminData returnval = null;

        UserDataLocal data = null;

        try {
            data = home.findBySubjectEmail(email);
        } catch (FinderException e) {
            log.debug("Cannot find user with Email='" + email + "'");
        }

        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to view user.
            if (!profileauthproxy.getEndEntityProfileAuthorization(admin,
                        data.getEndEntityProfileId(),
                        EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                throw new AuthorizationDeniedException("Administrator not authorized to view user.");
            }
        }

        if (data != null) {
            returnval = new UserAdminData(data.getUsername(), data.getSubjectDN(),
                    data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus(),
                    data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId(),
                    new java.util.Date(data.getTimeCreated()),
                    new java.util.Date(data.getTimeModified()), data.getTokenType(),
                    data.getHardTokenIssuerId());
            returnval.setPassword(data.getClearPassword());
        }

        debug("<findUserByEmail(" + email + ")");

        return returnval;
    }
     // findUserBySubjectDN

    /**
     * Implements IUserAdminSession::checkIfCertificateBelongToAdmin.
     *
     * @param admin DOCUMENT ME!
     * @param certificatesnr DOCUMENT ME!
     */
    public void checkIfCertificateBelongToAdmin(Admin admin, BigInteger certificatesnr)
        throws AuthorizationDeniedException, RemoteException {
        debug(">checkIfCertificateBelongToAdmin(" + certificatesnr + ")");

        String username = certificatesession.findUsernameByCertSerno(admin, certificatesnr);

        UserAdminData returnval = null;

        UserDataLocal data = null;

        if (username != null) {
            UserDataPK pk = new UserDataPK(username);

            try {
                data = home.findByPrimaryKey(pk);
            } catch (FinderException e) {
                log.debug("Cannot find user with username='" + username + "'");
            }
        }

        if (data != null) {
            int type = data.getType();

            if ((type & SecConst.USER_ADMINISTRATOR) == 0) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ADMINISTRATORLOGGEDIN,
                    "Certificate didn't belong to an administrator.");
                throw new AuthorizationDeniedException(
                    "Your certificate does not belong to an administrator.");
            }
        } else {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                LogEntry.EVENT_ERROR_ADMINISTRATORLOGGEDIN, "Certificate didn't belong to any user.");
            throw new AuthorizationDeniedException("Your certificate does not belong to any user.");
        }

        debug("<checkIfCertificateBelongToAdmin()");
    }
     // checkIfCertificateBelongToAdmin

    /**
     * Implements IUserAdminSession::findAllUsersByStatus.
     *
     * @param admin DOCUMENT ME!
     * @param status DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findAllUsersByStatus(Admin admin, int status)
        throws FinderException, RemoteException {
        debug(">findAllUsersByStatus(" + status + ")");
        debug("Looking for users with status: " + status);

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where status=?");
            ps.setInt(1, status);

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            while (rs.next()) {
                UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(10), rs.getInt(11), new java.util.Date(rs.getLong(8)),
                        new java.util.Date(rs.getLong(9)), rs.getInt(12), rs.getInt(13));
                data.setPassword(rs.getString(7));

                if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                    // Check if administrator is authorized to view user.
                    if (profileauthproxy.getEndEntityProfileAuthorization(admin,
                                data.getEndEntityProfileId(),
                                EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                        returnval.add(data);
                    }
                } else {
                    returnval.add(data);
                }
            }

            debug("found " + returnval.size() + " user(s) with status=" + status);
            debug("<findAllUsersByStatus(" + status + ")");

            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }
     // findAllUsersByStatus

    /**
     * Implements IUserAdminSession::findAllUsersWithLimit.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findAllUsersWithLimit(Admin admin)
        throws FinderException, RemoteException {
        debug(">findAllUsersWithLimit()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData");

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            while (rs.next() &&
                    (returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT)) {
                UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(10), rs.getInt(11), new java.util.Date(rs.getLong(8)),
                        new java.util.Date(rs.getLong(9)), rs.getInt(12), rs.getInt(13));
                data.setPassword(rs.getString(7));

                if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                    // Check if administrator is authorized to view user.
                    if (profileauthproxy.getEndEntityProfileAuthorization(admin,
                                data.getEndEntityProfileId(),
                                EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                        returnval.add(data);
                    }
                } else {
                    returnval.add(data);
                }
            }

            debug("<findAllUsersWithLimit()");

            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }

    /**
     * Implements IUserAdminSession::findAllUsersWithLimit.
     *
     * @param admin DOCUMENT ME!
     * @param status DOCUMENT ME!
     * @param onlybatchusers DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findAllUsersByStatusWithLimit(Admin admin, int status, boolean onlybatchusers)
        throws FinderException, RemoteException {
        debug(">findAllUsersByStatusWithLimit()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where status=?");
            ps.setInt(1, status);

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            while (rs.next() &&
                    (returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT)) {
                UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(10), rs.getInt(11), new java.util.Date(rs.getLong(8)),
                        new java.util.Date(rs.getLong(9)), rs.getInt(12), rs.getInt(13));
                data.setPassword(rs.getString(7));

                if (!onlybatchusers ||
                        ((data.getPassword() != null) && (data.getPassword().length() > 0))) {
                    if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                        // Check if administrator is authorized to view user.
                        if (profileauthproxy.getEndEntityProfileAuthorization(admin,
                                    data.getEndEntityProfileId(),
                                    EndEntityProfileAuthorizationProxy.VIEW_RIGHTS,
                                    LogEntry.MODULE_RA)) {
                            returnval.add(data);
                        }
                    } else {
                        returnval.add(data);
                    }
                }
            }

            debug("<findAllUsersByStatusWithLimit()");

            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }

    /**
     * Implements IUserAdminSession::startExternalService.
     *
     * @param args DOCUMENT ME!
     */
    public void startExternalService(String[] args) {
        debug(">startService()");

        try {
            RMIFactory rmiFactory = (RMIFactory) Class.forName((String) lookup(
                        "java:comp/env/RMIFactory", java.lang.String.class)).newInstance();
            rmiFactory.startConnection(args);
            debug(">startService()");
        } catch (Exception e) {
            error("Error starting external service.", e);
            throw new EJBException("Error starting external service", e);
        }
    }
     // startExternalService

    /**
     * Method to execute a customized query on the ra user data. The parameter query should be a
     * legal Query object.
     *
     * @param admin DOCUMENT ME!
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     *
     * @return a collection of UserAdminData. Maximum size of Collection is defined i
     *         IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     *
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     *
     * @see se.anatom.ejbca.util.query.Query
     */
    public Collection query(Admin admin, Query query) throws IllegalQueryException, RemoteException {
        debug(">query()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        // Check if query is legal.
        if (!query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where " +
                    query.getQueryString());

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            while (rs.next() &&
                    (returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT)) {
                UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6),
                        rs.getInt(10), rs.getInt(11), new java.util.Date(rs.getLong(8)),
                        new java.util.Date(rs.getLong(9)), rs.getInt(12), rs.getInt(13));
                data.setPassword(rs.getString(7));

                if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                    // Check if administrator is authorized to view user.
                    if (profileauthproxy.getEndEntityProfileAuthorization(admin,
                                data.getEndEntityProfileId(),
                                EndEntityProfileAuthorizationProxy.VIEW_RIGHTS, LogEntry.MODULE_RA)) {
                        returnval.add(data);
                    }
                } else {
                    returnval.add(data);
                }
            }

            debug("<query()");

            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }
     // query

    /**
     * Methods that checks if a user exists in the database having the given endentityprofileid.
     * This function is mainly for avoiding desyncronisation when a end entity profile is deleted.
     *
     * @param admin DOCUMENT ME!
     * @param endentityprofileid the id of end entity profile to look for.
     *
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid) {
        debug(">checkForEndEntityProfileId()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_ENDENTITYPROFILE, BasicMatch.MATCH_TYPE_EQUALS,
            Integer.toString(endentityprofileid));

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where " +
                    query.getQueryString());

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }

            debug("<checkForEndEntityProfileId()");

            return count > 0;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }

    /**
     * Methods that checks if a user exists in the database having the given certificateprofileid.
     * This function is mainly for avoiding desyncronisation when a certificateprofile is deleted.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofileid the id of certificateprofile to look for.
     *
     * @return true if certificateproileid exists in userdatabase.
     */
    public boolean checkForCertificateProfileId(Admin admin, int certificateprofileid) {
        debug(">checkForCertificateProfileId()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, BasicMatch.MATCH_TYPE_EQUALS,
            Integer.toString(certificateprofileid));

        try {
            // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where " +
                    query.getQueryString());

            // Execute query.
            rs = ps.executeQuery();

            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }

            debug("<checkForCertificateProfileId()");

            return count > 0;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
        }
    }
     // checkForCertificateProfileId

    /**
     * Loads the global configuration from the database.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public GlobalConfiguration loadGlobalConfiguration(Admin admin) {
        debug(">loadGlobalConfiguration()");

        GlobalConfiguration ret = null;

        try {
            GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey("0");

            if (gcdata != null) {
                ret = gcdata.getGlobalConfiguration();
            }
        } catch (javax.ejb.FinderException fe) {
            // Create new configuration
            ret = new GlobalConfiguration();
        }

        debug("<loadGlobalConfiguration()");

        return ret;
    }
     //loadGlobalConfiguration

    /**
     * Saves global configuration to the database.
     *
     * @param admin DOCUMENT ME!
     * @param globalconfiguration DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globalconfiguration) {
        debug(">saveGlobalConfiguration()");

        String pk = "0";

        try {
            GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey(pk);
            gcdata.setGlobalConfiguration(globalconfiguration);

            try {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_EDITSYSTEMCONFIGURATION, "");
            } catch (RemoteException re) {
            }
        } catch (javax.ejb.FinderException fe) {
            // Global configuration doesn't yet exists.
            try {
                GlobalConfigurationDataLocal data1 = globalconfigurationhome.create(pk,
                        globalconfiguration);

                try {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                        LogEntry.EVENT_INFO_EDITSYSTEMCONFIGURATION, "");
                } catch (RemoteException re) {
                }
            } catch (CreateException e) {
                try {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_EDITSYSTEMCONFIGURATION, "");
                } catch (RemoteException re) {
                }
            }
        }

        this.globalconfiguration = globalconfiguration;
        debug("<saveGlobalConfiguration()");
    }
     // saveGlobalConfiguration

    private int makeType(boolean administrator, boolean keyrecoverable, boolean sendnotification) {
        int returnval = SecConst.USER_ENDUSER;

        if (administrator) {
            returnval += SecConst.USER_ADMINISTRATOR;
        }

        if (keyrecoverable) {
            returnval += SecConst.USER_KEYRECOVERABLE;
        }

        if (sendnotification) {
            returnval += SecConst.USER_SENDNOTIFICATION;
        }

        return returnval;
    }
     // makeType

    private void sendNotification(Admin admin, String username, String password, String dn,
        String subjectaltname, String email) {
        try {
            if (email == null) {
                throw new Exception("Notification cannot be sent to user where email field is null");
            }

            javax.mail.Session mailSession = (javax.mail.Session) new InitialContext().lookup(
                    "java:comp/env/mail/DefaultMail");
            javax.mail.Message msg = new MimeMessage(mailSession);
            msg.setFrom(new InternetAddress(notificationcreator.getSender()));
            msg.setRecipients(javax.mail.Message.RecipientType.TO,
                InternetAddress.parse(email, false));
            msg.setSubject(notificationcreator.getSubject());
            msg.setContent(notificationcreator.getMessage(username, password, dn, subjectaltname,
                    email), "text/plain");
            msg.setHeader("X-Mailer", "JavaMailer");
            msg.setSentDate(new java.util.Date());
            Transport.send(msg);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                LogEntry.EVENT_INFO_NOTIFICATION, "Notification to " + email +
                " sent successfully.");
        } catch (Exception e) {
            try {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_NOTIFICATION, "Error when sending notification to " +
                    email);
            } catch (Exception f) {
                throw new EJBException(f);
            }
        }
    }
     // sendNotification
}
 // LocalUserAdminSessionBean
