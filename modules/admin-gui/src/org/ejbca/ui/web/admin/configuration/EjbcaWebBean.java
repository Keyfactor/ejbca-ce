/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.ejb.EJBException;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.roles.ComplexRoleManagementSessionLocal;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.util.HTMLTools;

/**
 * The main bean for the web interface, it contains all basic functions.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class EjbcaWebBean implements Serializable {

    private static final long serialVersionUID = 1L;

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
    private static final String[] AUTHORIZED_RA_RESOURCES = { "/ra_functionality/view_end_entity", "/ra_functionality/edit_end_entity",
            "/ra_functionality/create_end_entity", "/ra_functionality/delete_end_entity", "/ra_functionality/revoke_end_entity",
            "/ra_functionality/view_end_entity_history", "/ra_functionality/view_hardtoken", "/ca_functionality/view_certificate",
            "/ra_functionality/keyrecovery" };

    private final EjbLocalHelper ejb = new EjbLocalHelper();
    private final AccessControlSessionLocal authorizationSession = ejb.getAccessControlSession();
    private final CAAdminSessionLocal caAdminSession = ejb.getCaAdminSession();
    private final CaSessionLocal caSession = ejb.getCaSession();
    private final CertificateProfileSessionLocal certificateProfileSession = ejb.getCertificateProfileSession();
    private final CertificateStoreSessionLocal certificateStoreSession = ejb.getCertificateStoreSession();
    private final ComplexAccessControlSessionLocal complexAccessControlSession = ejb.getComplexAccessControlSession();
    private final ComplexRoleManagementSessionLocal complexRoleManagementSession = ejb.getComplexRoleManagementSession();
    private final EndEntityProfileSessionLocal endEntityProfileSession = ejb.getEndEntityProfileSession();
    private final HardTokenSessionLocal hardTokenSession = ejb.getHardTokenSession();
    private final SecurityEventsLoggerSessionLocal auditSession = ejb.getSecurityEventsLoggerSession();
    private final PublisherSessionLocal publisherSession = ejb.getPublisherSession();
    private final RoleAccessSessionLocal roleAccessSession = ejb.getRoleAccessSession();
    private final RoleManagementSessionLocal roleManagementSession = ejb.getRoleManagementSession();
    private final UserAdminSessionLocal userAdminSession = ejb.getUserAdminSession();
    private final UserDataSourceSessionLocal userDataSourceSession = ejb.getUserDataSourceSession();
    private final GlobalConfigurationSessionLocal globalConfigurationSession = ejb.getGlobalConfigurationSession();
    private final WebAuthenticationProviderSessionLocal authenticationSession = ejb.getWebAuthenticationProviderSession();

    private AdminPreferenceDataHandler adminspreferences;
    private AdminPreference currentadminpreference;
    private GlobalConfiguration globalconfiguration;
    private ServletContext servletContext = null;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private AuthorizationDataHandler authorizedatahandler;
    private WebLanguages adminsweblanguage;
    private String usercommonname = "";
    private String certificatefingerprint;
    /** Certificates for administrator logging into admin-GUI */
    private X509Certificate[] certificates;
    private InformationMemory informationmemory;
    private boolean initialized = false;
    private boolean errorpage_initialized = false;
    private Boolean[] raauthorized;
    private AuthenticationToken administrator;
    private String requestServerName;

    /*
     * We should make this configurable, so GUI client can use their own time zone rather than the
     * servers. Using JavaScript's "new Date().getTimezoneOffset()" in a cookie will not work on
     * the first load of the GUI, so a configurable parameter in the user's preferences is probably
     * the way to go.
     */
    private final TimeZone timeZone = ValidityDate.TIMEZONE_SERVER;

    /** Creates a new instance of EjbcaWebBean */
    public EjbcaWebBean() {
        initialized = false;
        raauthorized = new Boolean[AUTHORIZED_FIELD_LENGTH];
    }

    private void commonInit() throws Exception {
        if ((administrator == null) && (certificates == null)) {
            throw new AuthenticationFailedException("Client certificate required.");
        } else if ((certificates != null) && (administrator == null)) {
            final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(certificates[0]);
            AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
            administrator = authenticationSession.authenticate(subject);
            if (administrator == null) {
                throw new AuthenticationFailedException("Authorization failed for certificate: "+CertTools.getSubjectDN(certificates[0]));
            }        	
            //administrator = userAdminSession.getAdmin(certificates[0]);
        } // else we have already defined an administrator, for example in initialize_errorpage

        globaldataconfigurationdatahandler = new GlobalConfigurationDataHandler(administrator, globalConfigurationSession, authorizationSession);
        globalconfiguration = this.globaldataconfigurationdatahandler.loadGlobalConfiguration();
        if (informationmemory == null) {
            informationmemory = new InformationMemory(administrator, caAdminSession, caSession, authorizationSession, complexAccessControlSession,
                    endEntityProfileSession, hardTokenSession, publisherSession, userDataSourceSession, certificateProfileSession,
                    globalConfigurationSession, globalconfiguration);
        }
        authorizedatahandler = new AuthorizationDataHandler(administrator, informationmemory, roleAccessSession, roleManagementSession, complexRoleManagementSession,
                authorizationSession, complexAccessControlSession);

    }

    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String resource) throws Exception {

        certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates == null || certificates.length == 0) {
            throw new AuthenticationFailedException("Client certificate required.");
        }

        String userdn = "";

        if (!initialized) {
            requestServerName = getRequestServerName(request);

            commonInit(); // sets administrator object
            // Check if user certificate is valid and not revoked
            final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(certificates[0]);
            AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
            AuthenticationToken admin = authenticationSession.authenticate(subject);
            if (admin == null) {
                throw new AuthenticationFailedException("Authentication failed for certificate: "+CertTools.getSubjectDN(certificates[0]));
            }
            
            adminspreferences = new AdminPreferenceDataHandler(administrator);

            // Set ServletContext for reading language files from resources
            servletContext = request.getSession(true).getServletContext();

            // Check if certificate and user is an RA Admin
            userdn = CertTools.getSubjectDN(certificates[0]);
            if (log.isDebugEnabled()) {
                log.debug("Verifying authorization of '" + userdn + "'");
            }
            final String issuerDN = CertTools.getIssuerDN(certificates[0]);
            final String sernostr = CertTools.getSerialNumberAsString(certificates[0]);
            userAdminSession.checkIfCertificateBelongToUser(administrator, CertTools.getSerialNumber(certificates[0]), issuerDN);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            if (certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, CertTools.getSerialNumber(certificates[0])) == null) {
            	details.put("msg", "Logging in : Administrator Certificate is issued by external CA");
            }
            auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.SUCCESS, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                    administrator.toString(), Integer.toString(issuerDN.hashCode()), sernostr, null, details);
        }

        try {
            isAuthorized(URLDecoder.decode(resource, "UTF-8"));
        } catch (AuthorizationDeniedException e) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        } catch (EJBException e) {
            final Throwable cause = e.getCause();
            final String dbProblemMessage = getText("DATABASEDOWN");
            if (cause instanceof SQLException) {
                final Exception e1 = new Exception(dbProblemMessage);
                e1.initCause(e);
                throw e1;
            } else if (cause.getMessage().indexOf("SQLException", 0) >= 0) {
                final Exception e1 = new Exception(dbProblemMessage);
                e1.initCause(e);
                throw e1;
            }
            throw e;
        }

        if (!initialized) {
            certificatefingerprint = CertTools.getFingerprintAsString(certificates[0]);

            // Get current admin preference.
            currentadminpreference = null;
            if (certificatefingerprint != null) {
                currentadminpreference = adminspreferences.getAdminPreference(certificatefingerprint);
            }
            if (currentadminpreference == null) {
                currentadminpreference = adminspreferences.getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                    currentadminpreference.getSecondaryLanguage());

            // set User Common Name
            DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
            usercommonname = dn.getField(DNFieldExtractor.CN, 0);

            initialized = true;
        }
        return globalconfiguration;
    }

    /**
     * Method that returns the servername, extracted from the HTTPServlet Request, no protocol, port or application path is returned
     * 
     * @return the server name requested
     */
    private String getRequestServerName(HttpServletRequest request) {
        String requestURL = request.getRequestURL().toString();

        // Remove https://
        requestURL = requestURL.substring(8);
        int firstSlash = requestURL.indexOf("/");
        // Remove application path
        requestURL = requestURL.substring(0, firstSlash);

        return requestURL;
    }

    public GlobalConfiguration initialize_errorpage(HttpServletRequest request) throws Exception {

        if (!errorpage_initialized) {

            if (administrator == null) {
                String remoteAddr = request.getRemoteAddr();
                administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Public web user: " + remoteAddr));
            }
            commonInit();

            adminspreferences = new AdminPreferenceDataHandler(administrator);

            // Set ServletContext for reading language files from resources
            servletContext = request.getSession(true).getServletContext();

            if (currentadminpreference == null) {
                currentadminpreference = adminspreferences.getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                    currentadminpreference.getSecondaryLanguage());
            errorpage_initialized = true;
        }
        return globalconfiguration;
    }

    /** Returns the current users common name */
    public String getUsersCommonName() {
        return usercommonname;
    }

    /** Returns the users certificate serialnumber, user to id the adminpreference. */
    public String getCertificateFingerprint() {
        return certificatefingerprint;
    }

    /** Return the admins selected theme including it's trailing '.css' */
    public String getCssFile() {
        return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentadminpreference.getTheme() + ".css";
    }

    /** Return the IE fixes CSS of the admins selected theme including it's trailing '.css' */
    public String getIeFixesCssFile() {
        return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentadminpreference.getTheme()
                + globalconfiguration.getIeCssFilenamePostfix() + ".css";
    }

    /** Returns the admins prefered language */
    public int getPreferedLanguage() {
        return currentadminpreference.getPreferedLanguage();
    }

    /** Returns the admins secondary language. */
    public int getSecondaryLanguage() {
        return currentadminpreference.getSecondaryLanguage();
    }

    public int getEntriesPerPage() {
        return currentadminpreference.getEntriesPerPage();
    }

    public int getLogEntriesPerPage() {
        return currentadminpreference.getLogEntriesPerPage();
    }

    public void setLogEntriesPerPage(int logentriesperpage) throws Exception {
        currentadminpreference.setLogEntriesPerPage(logentriesperpage);
        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint, currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    public int getLastFilterMode() {
        return currentadminpreference.getLastFilterMode();
    }

    public void setLastFilterMode(int lastfiltermode) throws Exception {
        currentadminpreference.setLastFilterMode(lastfiltermode);
        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint, currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    public int getLastLogFilterMode() {
        return currentadminpreference.getLastLogFilterMode();
    }

    public void setLastLogFilterMode(int lastlogfiltermode) throws Exception {
        currentadminpreference.setLastLogFilterMode(lastlogfiltermode);
        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint, currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    public int getLastEndEntityProfile() {
        return currentadminpreference.getLastProfile();
    }

    public void setLastEndEntityProfile(int lastprofile) throws Exception {
        currentadminpreference.setLastProfile(lastprofile);
        if (existsAdminPreference()) {
            adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint, currentadminpreference);
        } else {
            addAdminPreference(currentadminpreference);
        }
    }

    /**
     * Checks if the admin have authorization to view the resource Does not return false if not authorized, instead throws an
     * AuthorizationDeniedException.
     * 
     * TODO: don't use as is in a new admin GUI, refactor to return true or false instead (if we re-use this class at all)
     * 
     * @return true if is authorized to resource, throws AuthorizationDeniedException if not authorized, never returns false.
     * @throws AuthorizationDeniedException is not authorized to resource
     */
    public boolean isAuthorized(String resource) throws AuthorizationDeniedException {
        if (certificates != null) {
            if (!authorizationSession.isAuthorized(administrator, resource)) {
                throw new AuthorizationDeniedException("Not authorized to " + resource);
            }
        } else {
            throw new AuthorizationDeniedException("Client certificate required.");
        }
        return true;
    }

    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Used by menu page Does not return false if not
     * authorized, instead throws an AuthorizationDeniedException.
     * 
     * TODO: don't use as is in a new admin GUI, refactor to return true or false instead (if we re-use this class at all)
     * 
     * @return true if is authorized to resource, throws AuthorizationDeniedException if not authorized, never returns false.
     * @throws AuthorizationDeniedException is not authorized to resource
     */
    public boolean isAuthorizedNoLog(String resource) throws AuthorizationDeniedException {
        if (certificates != null) {
            if (!authorizationSession.isAuthorizedNoLogging(administrator, resource)) {
                throw new AuthorizationDeniedException("Not authorized to " + resource);
            }
        } else {
            throw new AuthorizationDeniedException("Client certificate required");
        }
        return true;
    }

    /**
     * A more optimized authorization version to check if the admin have authorization to view the url without performing any logging. AUTHORIZED_RA..
     * constants should be used. Does not return false if not authorized, instead throws an AuthorizationDeniedException.
     * 
     * TODO: don't use as is in a new admin GUI, refactor to return true or false instead (if we re-use this class at all)
     * 
     * @return true is authorized to resource, never return false instead throws AuthorizationDeniedException.
     * @throws AuthorizationDeniedException is not authorized to resource
     */
    public boolean isAuthorizedNoLog(int resource) throws AuthorizationDeniedException {
        boolean returnval = false;
        if (certificates != null) {
            if (raauthorized[resource] == null) {
                // We don't bother to lookup the admin's username and email for this check..
                Set<X509Certificate> credentials = new HashSet<X509Certificate>();
                credentials.add(certificates[0]);
                Set<X500Principal> principals = new HashSet<X500Principal>();
                principals.add(certificates[0].getSubjectX500Principal());
                AuthenticationToken admin = new X509CertificateAuthenticationToken(principals, credentials);
                raauthorized[resource] = Boolean.valueOf(authorizationSession.isAuthorizedNoLogging(admin, AUTHORIZED_RA_RESOURCES[resource]));
            }
            returnval = raauthorized[resource].booleanValue();
        } else {
            throw new AuthorizationDeniedException("Client certificate required.");
        }
        if (!returnval) {
            throw new AuthorizationDeniedException("Not authorized to " + resource);
        }
        return returnval;
    }

    public String getBaseUrl() {
        return globalconfiguration.getBaseUrl(requestServerName);
    }

    public String getReportsPath() {
        return globalconfiguration.getReportsPath();
    }

    /* Returns the current admins preference */
    public AdminPreference getAdminPreference() throws Exception {
        AdminPreference returnval = adminspreferences.getAdminPreference(certificatefingerprint);
        if (returnval == null) {
            returnval = currentadminpreference;
        }
        return returnval;
    }

    /* Returns the admin preferences database */
    public AdminPreferenceDataHandler getAdminPreferences() {
        return adminspreferences;
    }

    public AuthorizationDataHandler getAuthorizationDataHandler() {
        return authorizedatahandler;
    }

    /* Returns the global configuration */
    public GlobalConfiguration getGlobalConfiguration() {
        return this.informationmemory.getGlobalConfiguration();
    }

    /**
     * A functions that returns wanted helpfile in prefered language. The parameter helpfilename should the wanted filename without language infix.
     * For example: given helpfilename 'cahelp.html' would return 'cahelp.en.html' if english was the users prefered language.
     */
    public String getHelpfileInfix(String helpfilename) {
        String returnedurl = null;
        String[] strs = adminsweblanguage.getAvailableLanguages();
        int index = currentadminpreference.getPreferedLanguage();
        String prefered = strs[index];
        prefered = prefered.toLowerCase();
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();

        String helpfile = helpfilename.substring(0, helpfilename.lastIndexOf('.'));
        String postfix = helpfilename.substring(helpfilename.lastIndexOf('.') + 1);

        String preferedfilename = "/" + globalconfiguration.getHelpPath() + "/" + helpfile + "." + prefered + "." + postfix;

        String preferedurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" + helpfile + "."
                + prefered + "." + postfix;

        String secondaryurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" + helpfile + "."
                + secondary + "." + postfix;

        if (this.getClass().getResourceAsStream(preferedfilename) != null) {
            returnedurl = preferedurl;
        } else {
            returnedurl = secondaryurl;
        }
        return returnedurl;
    }

    /**
     * A functions that returns wanted imagefile in prefered language and theme. If none of the language specific images are found the original
     * imagefilename will be returned.
     * 
     * The priority of filenames are int the following order 1. imagename.theme.preferedlanguage.jpg/gif 2. imagename.theme.secondarylanguage.jpg/gif
     * 3. imagename.theme.jpg/gif 4. imagename.preferedlanguage.jpg/gif 5. imagename.secondarylanguage.jpg/gif 6. imagename.jpg/gif
     * 
     * The parameter imagefilename should the wanted filename without language infix. For example: given imagefilename 'caimg.gif' would return
     * 'caimg.en.gif' if english was the users prefered language. It's important that all letters i imagefilename is lowercase.
     */

    public String getImagefileInfix(String imagefilename) {
        String returnedurl = null;
        String[] strs = adminsweblanguage.getAvailableLanguages();
        int index = currentadminpreference.getPreferedLanguage();
        String prefered = strs[index];
        prefered = prefered.toLowerCase();
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();

        String imagefile = imagefilename.substring(0, imagefilename.lastIndexOf('.'));
        String theme = currentadminpreference.getTheme().toLowerCase();
        String postfix = imagefilename.substring(imagefilename.lastIndexOf('.') + 1);

        String preferedthemefilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + prefered + "." + postfix;
        String secondarythemefilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + secondary + "." + postfix;
        String themefilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + postfix;

        String preferedfilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + prefered + "." + postfix;

        String secondaryfilename = "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + secondary + "." + postfix;

        String preferedthemeurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + theme + "." + prefered + "." + postfix;

        String secondarythemeurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + theme + "." + secondary + "." + postfix;

        String imagethemeurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + theme + "." + postfix;

        String preferedurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + prefered + "." + postfix;

        String secondaryurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + secondary + "." + postfix;

        String imageurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getImagesPath() + "/" + imagefile + "."
                + postfix;
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

    public String[] getAvailableLanguages() {
        return adminsweblanguage.getAvailableLanguages();
    }

    public String getText(String template) {
        return adminsweblanguage.getText(template);
    }

    /**
     * @param template the entry in the language file to get
     * @param unescape true if html entities should be unescaped (&auml; converted to the real char)
     * @return text string, possibly unescaped, or "template" if the template does not match any entry in the language files
     */
    public String getText(String template, boolean unescape) {
        String str = getText(template);
        if (unescape == true) {
            str = HTMLTools.htmlunescape(str);
            // log.debug("String after unescape: "+str);
            // If unescape == true it most likely means we will be displaying a javascript
            str = HTMLTools.javascriptEscape(str);
            // log.debug("String after javascriptEscape: "+str);
        }
        return str;
    }

    /** @return a more user friendly representation of a Date. */
    public String formatAsISO8601(final Date date) {
        return ValidityDate.formatAsISO8601(date, timeZone);
    }

    /** Parse a Date and reformat it as vailidation. */
    public String validateDateFormat(String value) throws ParseException {
        return ValidityDate.formatAsUTC(ValidityDate.parseAsUTC(value));
    }

    /** Check if the argument is a relative date/time in the form days:min:seconds. */
    public boolean isRelativeDateTime(final String dateString) {
        return dateString.matches("^\\d+:\\d?\\d:\\d?\\d$");
    }

    /** To be used when giving format example. */
    public String getDateExample() {
        return "[" + ValidityDate.ISO8601_DATE_FORMAT + "]: '" + formatAsISO8601(new Date()) + "'";
    }

    /** Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. */
    public String getImpliedUTCFromISO8601(final String dateString) throws ParseException {
        return ValidityDate.getImpliedUTCFromISO8601(dateString);
    }

    /**
     * Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. If it is a relative date we
     * return it as it was. Otherwise we try to parse it as a ISO8601 date time.
     */
    public String getImpliedUTCFromISO8601OrRelative(final String dateString) throws ParseException {
        if (!isRelativeDateTime(dateString)) {
            return getImpliedUTCFromISO8601(dateString);
        }
        return dateString;
    }

    /** Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". */
    public String getISO8601FromImpliedUTC(final String dateString) throws ParseException {
        return ValidityDate.getISO8601FromImpliedUTC(dateString, timeZone);
    }

    /**
     * Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". If it is a relative date we
     * return it as it was. If we fail to parse the stored date we return an error-string followed by the stored value.
     */
    public String getISO8601FromImpliedUTCOrRelative(final String dateString) {
        if (!isRelativeDateTime(dateString)) {
            try {
                return getISO8601FromImpliedUTC(dateString);
            } catch (ParseException e) {
                log.debug(e.getMessage());
                // If we somehow managed to store an invalid date, we want to give the admin the option
                // to correct this. If we just throw an Exception here it would not be possible.
                return "INVALID: " + dateString;
            }
        }
        return dateString;
    }

    public void reloadGlobalConfiguration() throws Exception {
        globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
        informationmemory.systemConfigurationEdited(globalconfiguration);
    }

    public void saveGlobalConfiguration() throws Exception {
        globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);
        informationmemory.systemConfigurationEdited(globalconfiguration);
    }

    public boolean existsAdminPreference() throws Exception {
        return adminspreferences.existsAdminPreference(certificatefingerprint);
    }

    public void addAdminPreference(AdminPreference ap) throws Exception {
        currentadminpreference = ap;
        adminspreferences.addAdminPreference(certificatefingerprint, ap);
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    public Collection<Integer> getAuthorizedCAIds() {
        return this.informationmemory.getAuthorizedCAIds();
    }

    public void changeAdminPreference(AdminPreference ap) throws Exception {
        currentadminpreference = ap;
        adminspreferences.changeAdminPreference(certificatefingerprint, ap);
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    public AdminPreference getDefaultAdminPreference() throws Exception {
        return adminspreferences.getDefaultAdminPreference();
    } // getDefaultAdminPreference()

    public void saveDefaultAdminPreference(AdminPreference dap) throws Exception {
        adminspreferences.saveDefaultAdminPreference(dap);

        // Reload preferences
        currentadminpreference = adminspreferences.getAdminPreference(certificatefingerprint);
        if (currentadminpreference == null) {
            currentadminpreference = adminspreferences.getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    } // saveDefaultAdminPreference

    public InformationMemory getInformationMemory() {
        return this.informationmemory;
    }

    public AuthenticationToken getAdminObject() {
        return this.administrator;
    }

    /**
     * Method returning all CA ids with CMS service enabled
     */
    public Collection<Integer> getCAIdsWithCMSServiceActive() {
        ArrayList<Integer> retval = new ArrayList<Integer>();
        Collection<Integer> caids = caSession.getAvailableCAs(administrator);
        Iterator<Integer> iter = caids.iterator();
        while (iter.hasNext()) {
            Integer caid = iter.next();
            retval.add(caid);
        }
        return retval;
    }

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public boolean isUsingExportableCryptography() {
        return KeyTools.isUsingExportableCryptography();
    }

    /**
     * @return The host's name or "unknown" if it could not be determined.
     */
    public String getHostName() {
        String hostname = "unknown";
        try {
            InetAddress addr = InetAddress.getLocalHost();
            // Get hostname
            hostname = addr.getHostName();
        } catch (UnknownHostException e) {
            // Ignored
        }
        return hostname;
    }

    /** @return The current time on the server */
    public String getServerTime() {
        return ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_SERVER);
    }

    /**
     * Uses the language in the Administration GUI to determine which locale is preferred.
     * 
     * @return the locale of the Admin GUI
     */
    public Locale getLocale() {
        Locale[] locales = DateFormat.getAvailableLocales(); // TODO: Why not use Locale.getAvailableLocales()? Difference?
        Locale returnValue = null;
        String prefered = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getPreferedLanguage()].toLowerCase();
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();
        if (prefered.equalsIgnoreCase("se")) {
            prefered = "SV";
        }
        if (secondary.equalsIgnoreCase("se")) {
            secondary = "SV";
        }
        for (int i = 0; i < locales.length; i++) {
            if (locales[i].getLanguage().equalsIgnoreCase(prefered)) {
                returnValue = locales[i];
            } else if (returnValue == null && locales[i].getLanguage().equalsIgnoreCase(secondary)) {
                returnValue = locales[i];
            }
        }
        if (returnValue == null) {
            returnValue = Locale.US;
        }
        return returnValue;
    }

    public boolean isHelpEnabled() {
        return !"disabled".equalsIgnoreCase(GlobalConfiguration.HELPBASEURI);
    }

    public String getHelpBaseURI() {
        String helpBaseURI = GlobalConfiguration.HELPBASEURI;
        if ("internal".equalsIgnoreCase(helpBaseURI)) {
            return getBaseUrl() + "doc";
        } else {
            return helpBaseURI;
        }
    }

    public String getHelpReference(String lastPart) {
        if (!isHelpEnabled()) {
            return "";
        }
        return "[<a href=\"" + getHelpBaseURI() + lastPart + "\" target=\"" + GlobalConfiguration.DOCWINDOW + "\" title=\""
                + getText("OPENHELPSECTION") + "\" >?</a>]";
    }

    public String[] getCertSernoAndIssuerdn(String certdata) {
        return StringTools.parseCertData(certdata);
    }

    public String getCleanOption(String parameter, String[] validOptions) throws Exception {
        for (int i = 0; i < validOptions.length; i++) {
            if (parameter.equals(validOptions[i])) {
                return parameter;
            }
        }
        throw new Exception("Trying to set an invalid option.");
    }

    public void clearClusterCache() throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">clearClusterCache");
        }
        Set<String> nodes = globalconfiguration.getNodesInCluster();
        final Iterator<String> itr = nodes.iterator();
        String host = null;
        while (itr.hasNext()) {
            host = (String) itr.next();
            if (host != null) {
                // get http port of remote host, this requires that all cluster nodes uses the same public htt port
                int pubport = WebConfiguration.getPublicHttpPort();
                String requestUrl = "http://" + host + ":" + pubport + "/ejbca/clearcache?command=clearcaches";
                URL url = new URL(requestUrl);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                if (log.isDebugEnabled()) {
                    log.debug("Contacting host with url:" + requestUrl);
                }
                int responseCode = con.getResponseCode();
                if (responseCode != 200) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to clear caches for host: " + host + ", responseCode=" + responseCode);
                    }
                    throw new Exception("Failed to clear caches for host: " + host + ", responseCode=" + responseCode);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<clearClusterCache");
        }
    }

    public EjbLocalHelper getEjb() {
        return ejb;
    }
}
