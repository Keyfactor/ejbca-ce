package se.anatom.ejbca.webdist.webconfiguration;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.rmi.RemoteException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.*;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.authorization.AdminInformation;
import se.anatom.ejbca.ra.authorization.AuthenticationFailedException;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.CertTools;


/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @author Philip Vendil
 * @version $Id: EjbcaWebBean.java,v 1.30 2003-07-24 08:43:33 anatom Exp $
 */
public class EjbcaWebBean {
    private static Logger log = Logger.getLogger(EjbcaWebBean.class);

    // Public Constants.
    public static final int AUTHORIZED_RA_VIEW_RIGHTS = 0;
    public static final int AUTHORIZED_RA_EDIT_RIGHTS = 1;
    public static final int AUTHORIZED_RA_CREATE_RIGHTS = 2;
    public static final int AUTHORIZED_RA_DELETE_RIGHTS = 3;
    public static final int AUTHORIZED_RA_REVOKE_RIGHTS = 4;
    public static final int AUTHORIZED_RA_HISTORY_RIGHTS = 5;
    public static final int AUTHORIZED_HARDTOKEN_VIEW_RIGHTS = 6;
    public static final int AUTHORIZED_CA_VIEW_CERT = 7;
    public static final int AUTHORIZED_RA_KEYRECOVERY_RIGHTS = 8;
    private static final int AUTHORIZED_FIELD_LENGTH = 9;
    private static final String[] AUTHORIZED_RA_RESOURCES = {
        "/ra_functionallity/view_end_entity", "/ra_functionallity/edit_end_entity",
        "/ra_functionallity/create_end_entity", "/ra_functionallity/delete_end_entity",
        "/ra_functionallity/revoke_end_entity", "/ra_functionallity/view_end_entity_history",
        "/ra_functionallity/view_hardtoken", "/ca_functionallity/view_certificate",
        "/ra_functionallity/keyrecovery"
    };

    // Private Fields.
    private ILogSessionRemote logsession;
    private AdminPreferenceDataHandler adminspreferences;
    private AdminPreference currentadminpreference;
    private GlobalConfiguration globalconfiguration;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private AuthorizationDataHandler authorizedatahandler;
    private WebLanguages weblanguages;
    private WebLanguages adminsweblanguage;
    private String usercommonname = "";
    private BigInteger certificateserialnumber;
    private X509Certificate[] certificates;
    private boolean initialized = false;
    private boolean errorpage_initialized = false;
    private Boolean[] raauthorized;

    /**
     * Creates a new instance of EjbcaWebBean
     */
    public EjbcaWebBean()
        throws IOException, NamingException, CreateException, FinderException, RemoteException {
        initialized = false;
        raauthorized = new Boolean[AUTHORIZED_FIELD_LENGTH];
    }

    // Public Methods.

    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String resource)
        throws Exception {
        String userdn = "";

        CertificateFactory certfact = CertificateFactory.getInstance("X.509");
        certificates = (X509Certificate[]) request.getAttribute(
                "javax.servlet.request.X509Certificate");

        if (certificates == null) {
            throw new AuthenticationFailedException("Client certificate required.");
        }

        // Check if certificate is still valid
        if (!initialized) {
            Admin administrator = new Admin(certificates[0]);

            InitialContext jndicontext = new InitialContext();
            Object obj1 = jndicontext.lookup("UserAdminSession");
            IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    IUserAdminSessionHome.class);
            IUserAdminSessionRemote adminsession = adminsessionhome.create();
            obj1 = jndicontext.lookup("LogSession");

            ILogSessionHome logsessionhome = (ILogSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ILogSessionHome.class);
            logsession = logsessionhome.create();

            globaldataconfigurationdatahandler = new GlobalConfigurationDataHandler(adminsession,
                    administrator);
            globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
            adminspreferences = new AdminPreferenceDataHandler(administrator);
            weblanguages = new WebLanguages(globalconfiguration);

            userdn = CertTools.getSubjectDN(certificates[0]);

            // Check if user certificate is revoked
            authorizedatahandler = new AuthorizationDataHandler(globalconfiguration, logsession,
                    administrator);
            authorizedatahandler.authenticate(certificates[0]);

            // Check if certificate belongs to a RA Admin
            log.debug("Verifying authoirization of '" + userdn);

            // Check that user is administrator.
            adminsession.checkIfCertificateBelongToAdmin(administrator,
                certificates[0].getSerialNumber());

            logsession.log(administrator, LogEntry.MODULE_ADMINWEB, new java.util.Date(), null,
                null, LogEntry.EVENT_INFO_ADMINISTRATORLOGGEDIN, "");
        }

        try {
            isAuthorized(URLDecoder.decode(resource, "UTF-8"));
        } catch (AuthorizationDeniedException e) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        } catch (java.io.UnsupportedEncodingException e) {
        }

        if (!initialized) {
            certificateserialnumber = certificates[0].getSerialNumber();

            // Get current admin preference.
            currentadminpreference = null;

            if (certificateserialnumber != null) {
                currentadminpreference = adminspreferences.getAdminPreference(certificateserialnumber);
            }

            if (currentadminpreference == null) {
                currentadminpreference = adminspreferences.getDefaultAdminPreference();
            }

            adminsweblanguage = new WebLanguages(currentadminpreference.getPreferedLanguage(),
                    currentadminpreference.getSecondaryLanguage());

            // set User Common Name
            DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
            usercommonname = dn.getField(DNFieldExtractor.CN, 0);

            initialized = true;
        }

        return globalconfiguration;
    }

    /**
     * DOCUMENT ME!
     *
     * @param request DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public GlobalConfiguration initialize_errorpage(HttpServletRequest request)
        throws Exception {
        if (!errorpage_initialized) {
            String remoteAddr = request.getRemoteAddr();
            Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);

            InitialContext jndicontext = new InitialContext();
            Object obj1 = jndicontext.lookup("UserAdminSession");
            IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    IUserAdminSessionHome.class);
            IUserAdminSessionRemote adminsession = adminsessionhome.create();

            globaldataconfigurationdatahandler = new GlobalConfigurationDataHandler(adminsession,
                    administrator);
            globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
            adminspreferences = new AdminPreferenceDataHandler(administrator);
            weblanguages = new WebLanguages(globalconfiguration);

            if (currentadminpreference == null) {
                currentadminpreference = adminspreferences.getDefaultAdminPreference();
            }

            adminsweblanguage = new WebLanguages(currentadminpreference.getPreferedLanguage(),
                    currentadminpreference.getSecondaryLanguage());

            errorpage_initialized = true;
        }

        return globalconfiguration;
    }

    /**
     * Returns the current users common name
     *
     * @return DOCUMENT ME!
     */
    public String getUsersCommonName() {
        return usercommonname;
    }

    /**
     * Returns the users certificate serialnumber, user to id the adminpreference.
     *
     * @return DOCUMENT ME!
     */
    public String getCertificateSerialNumber() {
        return certificateserialnumber.toString(16);
    }

    /**
     * Return the admins selected theme including it's trailing '.css'
     *
     * @return DOCUMENT ME!
     */
    public String getCssFile() {
        return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" +
        currentadminpreference.getTheme() + ".css";
    }

    /**
     * Returns the admins prefered language
     *
     * @return DOCUMENT ME!
     */
    public int getPreferedLanguage() {
        return currentadminpreference.getPreferedLanguage();
    }

    /**
     * Returns the admins secondary language.
     *
     * @return DOCUMENT ME!
     */
    public int getSecondaryLanguage() {
        return currentadminpreference.getSecondaryLanguage();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getEntriesPerPage() {
        return currentadminpreference.getEntriesPerPage();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getLogEntriesPerPage() {
        return currentadminpreference.getLogEntriesPerPage();
    }

    /**
     * DOCUMENT ME!
     *
     * @param logentriesperpage DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void setLogEntriesPerPage(int logentriesperpage)
        throws Exception {
        currentadminpreference.setLogEntriesPerPage(logentriesperpage);

        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificateserialnumber,
                currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getLastFilterMode() {
        return currentadminpreference.getLastFilterMode();
    }

    /**
     * DOCUMENT ME!
     *
     * @param lastfiltermode DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void setLastFilterMode(int lastfiltermode) throws Exception {
        currentadminpreference.setLastFilterMode(lastfiltermode);

        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificateserialnumber,
                currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getLastLogFilterMode() {
        return currentadminpreference.getLastLogFilterMode();
    }

    /**
     * DOCUMENT ME!
     *
     * @param lastlogfiltermode DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void setLastLogFilterMode(int lastlogfiltermode)
        throws Exception {
        currentadminpreference.setLastLogFilterMode(lastlogfiltermode);

        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificateserialnumber,
                currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getLastEndEntityProfile() {
        return currentadminpreference.getLastProfile();
    }

    /**
     * DOCUMENT ME!
     *
     * @param lastprofile DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void setLastEndEntityProfile(int lastprofile)
        throws Exception {
        currentadminpreference.setLastProfile(lastprofile);

        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificateserialnumber,
                currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CloneNotSupportedException DOCUMENT ME!
     */
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    /* Checks if the admin have authorization to view the resource */
    public boolean isAuthorized(String resource) throws AuthorizationDeniedException {
        boolean returnval = false;

        if (certificates != null) {
            returnval = authorizedatahandler.isAuthorized(new AdminInformation(certificates[0]),
                    resource);
        } else {
            throw new AuthorizationDeniedException("Client certificate required.");
        }

        return returnval;
    }

    /* Checks if the admin have authorization to view the resource without performing any logging. Used by menu page */
    public boolean isAuthorizedNoLog(String resource) throws AuthorizationDeniedException {
        boolean returnval = false;

        if (certificates != null) {
            returnval = authorizedatahandler.isAuthorizedNoLog(new AdminInformation(certificates[0]),
                    resource);
        } else {
            throw new AuthorizationDeniedException("Client certificate required.");
        }

        return returnval;
    }

    /* A more optimezed authorization verison to check if the admin have authorization to view the url without performing any logging.
     * AUTHORIZED_RA.. contants should be used.*/
    public boolean isAuthorizedNoLog(int resource) throws AuthorizationDeniedException {
        boolean returnval = false;

        if (certificates != null) {
            if (raauthorized[resource] == null) {
                raauthorized[resource] = Boolean.valueOf(authorizedatahandler.isAuthorizedNoLog(
                            new AdminInformation(certificates[0]), AUTHORIZED_RA_RESOURCES[resource]));
            }

            returnval = raauthorized[resource].booleanValue();
        } else {
            throw new AuthorizationDeniedException("Client certificate required.");
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBaseUrl() {
        return globalconfiguration.getBaseUrl();
    }

    /* Returns the current admins preference */
    public AdminPreference getAdminPreference() throws Exception {
        AdminPreference returnval = adminspreferences.getAdminPreference(certificateserialnumber);

        if (returnval == null) {
            returnval = currentadminpreference;
        }

        return returnval;
    }

    /* Returns the admin preferences database */
    public AdminPreferenceDataHandler getAdminPreferences() {
        return adminspreferences;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AuthorizationDataHandler getAuthorizationDataHandler() {
        return authorizedatahandler;
    }

    /* Returns the global configuration */
    public GlobalConfiguration getGlobalConfiguration() {
        return globalconfiguration;
    }

    /**
     * A functions that returns wanted helpfile in prefered language. The parameter helpfilename
     * should the wanted filename without language infix. For example: given helpfilename
     * 'cahelp.html' would return 'cahelp.en.html' if english was the users prefered language.
     *
     * @param helpfilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHelpfileInfix(String helpfilename) {
        String returnedurl = null;
        String prefered = WebLanguages.getAvailableLanguages()[currentadminpreference.getPreferedLanguage()].toLowerCase();
        String secondary = WebLanguages.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();

        String helpfile = helpfilename.substring(0, helpfilename.lastIndexOf('.'));
        String postfix = helpfilename.substring(helpfilename.lastIndexOf('.') + 1);

        String preferedfilename = "/" + globalconfiguration.getHelpPath() + "/" + helpfile + "." +
            prefered + "." + postfix;

        String secondaryfilename = "/" + globalconfiguration.getHelpPath() + "/" + helpfile + "." +
            secondary + "." + postfix;

        String preferedurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" +
            helpfile + "." + prefered + "." + postfix;

        String secondaryurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" +
            helpfile + "." + secondary + "." + postfix;

        if (this.getClass().getResourceAsStream(preferedfilename) != null) {
            returnedurl = preferedurl;
        } else {
            returnedurl = secondaryurl;
        }

        return returnedurl;
    }

    /**
     * A functions that returns wanted imagefile in prefered language and theme. If none of the
     * language specific images are found the original imagefilename will be returned. The
     * priority of filenames are int the following order 1.
     * imagename.theme.preferedlanguage.jpg/gif 2. imagename.theme.secondarylanguage.jpg/gif 3.
     * imagename.theme.jpg/gif 4. imagename.preferedlanguage.jpg/gif 5.
     * imagename.secondarylanguage.jpg/gif 6. imagename.jpg/gif The parameter imagefilename should
     * the wanted filename without language infix. For example: given imagefilename 'caimg.gif'
     * would return 'caimg.en.gif' if english was the users prefered language. It's important that
     * all letters i imagefilename is lowercase.
     *
     * @param imagefilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getImagefileInfix(String imagefilename) {
        String returnedurl = null;
        String prefered = WebLanguages.getAvailableLanguages()[currentadminpreference.getPreferedLanguage()].toLowerCase();
        String secondary = WebLanguages.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();

        String imagefile = imagefilename.substring(0, imagefilename.lastIndexOf('.'));
        String theme = currentadminpreference.getTheme().toLowerCase();
        String postfix = imagefilename.substring(imagefilename.lastIndexOf('.') + 1);

        String preferedthemefilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile +
            "." + theme + "." + prefered + "." + postfix;
        String secondarythemefilename = "/" + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + theme + "." + secondary + "." + postfix;
        String themefilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." +
            theme + "." + postfix;

        String preferedfilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile +
            "." + prefered + "." + postfix;

        String secondaryfilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile +
            "." + secondary + "." + postfix;

        String preferedthemeurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + theme + "." + prefered + "." + postfix;

        String secondarythemeurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + theme + "." + secondary + "." + postfix;

        String imagethemeurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + theme + "." + postfix;

        String preferedurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + prefered + "." + postfix;

        String secondaryurl = globalconfiguration.getBaseUrl() +
            globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" +
            imagefile + "." + secondary + "." + postfix;

        String imageurl = globalconfiguration.getBaseUrl() + globalconfiguration.getAdminWebPath() +
            globalconfiguration.getImagesPath() + "/" + imagefile + "." + postfix;

        if (this.getClass().getResourceAsStream(preferedthemefilename) != null) {
            returnedurl = preferedthemeurl;
        } else {
            if (this.getClass().getResourceAsStream(secondarythemefilename) != null) {
                returnedurl = secondarythemeurl;
            } else {
                if (this.getClass().getResourceAsStream(themefilename) != null) {
                    returnedurl = imagethemeurl;
                } else {
                    if (this.getClass().getResourceAsStream(preferedfilename) != null) {
                        returnedurl = preferedurl;
                    } else {
                        if (this.getClass().getResourceAsStream(secondaryfilename) != null) {
                            returnedurl = secondaryurl;
                        } else {
                            returnedurl = imageurl;
                        }
                    }
                }
            }
        }

        return returnedurl;
    }

    /**
     * DOCUMENT ME!
     *
     * @param template DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getText(String template) {
        return adminsweblanguage.getText(template);
    }

    /**
     * DOCUMENT ME!
     *
     * @param date DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String printDate(Date date) {
        return DateFormat.getDateInstance(DateFormat.SHORT).format(date);
    }

    /**
     * DOCUMENT ME!
     *
     * @param date DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String printDateTime(Date date) {
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(date);
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void reloadGlobalConfiguration() throws Exception {
        globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void saveGlobalConfiguration() throws Exception {
        globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public boolean existsAdminPreference() throws Exception {
        return adminspreferences.existsAdminPreference(certificateserialnumber);
    }

    /**
     * DOCUMENT ME!
     *
     * @param ap DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void addAdminPreference(AdminPreference ap)
        throws Exception {
        currentadminpreference = ap;
        adminspreferences.addAdminPreference(certificateserialnumber, ap);
        adminsweblanguage = new WebLanguages(currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    /**
     * DOCUMENT ME!
     *
     * @param ap DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void changeAdminPreference(AdminPreference ap)
        throws Exception {
        currentadminpreference = ap;
        adminspreferences.changeAdminPreference(certificateserialnumber, ap);
        adminsweblanguage = new WebLanguages(currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public AdminPreference getDefaultAdminPreference()
        throws Exception {
        return adminspreferences.getDefaultAdminPreference();
    }

    // getDefaultAdminPreference()

    /**
     * DOCUMENT ME!
     *
     * @param dap DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void saveDefaultAdminPreference(AdminPreference dap)
        throws Exception {
        adminspreferences.saveDefaultAdminPreference(dap);

        // Reload preferences
        currentadminpreference = adminspreferences.getAdminPreference(certificateserialnumber);

        if (currentadminpreference == null) {
            currentadminpreference = adminspreferences.getDefaultAdminPreference();
        }

        adminsweblanguage = new WebLanguages(currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    // saveDefaultAdminPreference
}
