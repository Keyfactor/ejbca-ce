/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;

import javax.ejb.EJBException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.EnterpriseEjbLocalHelper;
import org.ejbca.util.HTMLTools;

/**
 * The main bean for the web interface, it contains all basic functions.
 * 
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

    private static final String[] AUTHORIZED_RA_RESOURCES = { AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRulesConstants.REGULAR_EDITENDENTITY,
            AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRulesConstants.REGULAR_REVOKEENDENTITY,
            AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRulesConstants.REGULAR_VIEWHARDTOKENS,
            AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRulesConstants.REGULAR_KEYRECOVERY };

    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private final EnterpriseEjbLocalHelper enterpriseEjbLocalHelper = new EnterpriseEjbLocalHelper();
    private final AccessControlSessionLocal authorizationSession = ejbLocalHelper.getAccessControlSession();
    private final CAAdminSessionLocal caAdminSession = ejbLocalHelper.getCaAdminSession();
    private final CaSessionLocal caSession = ejbLocalHelper.getCaSession();
    private final CertificateProfileSessionLocal certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
    private final CertificateStoreSessionLocal certificateStoreSession = ejbLocalHelper.getCertificateStoreSession();
    private final ComplexAccessControlSessionLocal complexAccessControlSession = ejbLocalHelper.getComplexAccessControlSession();
    private final EndEntityProfileSessionLocal endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
    private final HardTokenSessionLocal hardTokenSession = ejbLocalHelper.getHardTokenSession();
    private final SecurityEventsLoggerSessionLocal auditSession = ejbLocalHelper.getSecurityEventsLoggerSession();
    private final PublisherSessionLocal publisherSession = ejbLocalHelper.getPublisherSession();
    private final RoleAccessSessionLocal roleAccessSession = ejbLocalHelper.getRoleAccessSession();
    private final RoleManagementSessionLocal roleManagementSession = ejbLocalHelper.getRoleManagementSession();
    private final EndEntityManagementSessionLocal endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
    private final UpgradeSessionLocal upgradeSession = ejbLocalHelper.getUpgradeSession();
    private final UserDataSourceSessionLocal userDataSourceSession = ejbLocalHelper.getUserDataSourceSession();
    private final GlobalConfigurationSessionLocal globalConfigurationSession = ejbLocalHelper.getGlobalConfigurationSession();
    private final WebAuthenticationProviderSessionLocal authenticationSession = ejbLocalHelper.getWebAuthenticationProviderSession();

    private AdminPreferenceDataHandler adminspreferences;
    private AdminPreference currentadminpreference;
    private GlobalConfiguration globalconfiguration;
    private CmpConfiguration cmpconfiguration = null;
    private CmpConfiguration cmpConfigForEdit = null;
    private AvailableExtendedKeyUsagesConfiguration availableExtendedKeyUsagesConfig = null;
    private AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = null;
    private ServletContext servletContext = null;
    private AuthorizationDataHandler authorizedatahandler;
    private WebLanguages adminsweblanguage;
    private String usercommonname = "";
    private String certificatefingerprint; // Unique key to identify the admin.. usually a hash of the admin's certificate
    private InformationMemory informationmemory;
    private boolean initialized = false;
    private boolean errorpage_initialized = false;
    private final Boolean[] raauthorized = new Boolean[AUTHORIZED_RA_RESOURCES.length];
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
    }

    private void commonInit() throws Exception {
        reloadGlobalConfiguration();
        reloadCmpConfiguration();
        reloadAvailableExtendedKeyUsagesConfiguration();
        reloadAvailableCustomCertExtensionsConfiguration();
        if (informationmemory == null) {
            informationmemory = new InformationMemory(administrator, caAdminSession, caSession, authorizationSession, complexAccessControlSession,
                    endEntityProfileSession, hardTokenSession, publisherSession, userDataSourceSession, certificateProfileSession,
                    globalConfigurationSession, roleManagementSession, ejbLocalHelper.getApprovalProfileSession(), globalconfiguration, 
                    availableExtendedKeyUsagesConfig,
                    availableCustomCertExtensionsConfig, this);
        }
        authorizedatahandler = new AuthorizationDataHandler(administrator, informationmemory, roleAccessSession, roleManagementSession,
                authorizationSession);
    }

    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String... resources) throws Exception {
        if (!initialized) {
            requestServerName = getRequestServerName(request);
            if (log.isDebugEnabled()) {
                log.debug("requestServerName: "+requestServerName);
            }
            final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
            if (certificates == null || certificates.length == 0) {
                throw new AuthenticationFailedException("Client certificate required.");
            } else {
                final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
                credentials.add(certificates[0]);
                final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
                administrator = authenticationSession.authenticate(subject);
                if (administrator == null) {
                    throw new AuthenticationFailedException("Authentication failed for certificate: " + CertTools.getSubjectDN(certificates[0]));
                }
            }
            commonInit();
            adminspreferences = new AdminPreferenceDataHandler((X509CertificateAuthenticationToken) administrator);
            // Set ServletContext for reading language files from resources
            servletContext = request.getSession(true).getServletContext();
            // Check if certificate and user is an RA Admin
            final String userdn = CertTools.getSubjectDN(certificates[0]);
            final DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
            usercommonname = dn.getField(DNFieldExtractor.CN, 0);
            if (log.isDebugEnabled()) {
                log.debug("Verifying authorization of '" + userdn + "'");
            }
            final String issuerDN = CertTools.getIssuerDN(certificates[0]);
            final String sernostr = CertTools.getSerialNumberAsString(certificates[0]);
            final BigInteger serno = CertTools.getSerialNumber(certificates[0]);
            certificatefingerprint = CertTools.getFingerprintAsString(certificates[0]);
            // Check if certificate belongs to a user. checkIfCertificateBelongToUser will always return true if WebConfiguration.getRequireAdminCertificateInDatabase is set to false (in properties file)
            if (!endEntityManagementSession.checkIfCertificateBelongToUser(serno, issuerDN)) {
                throw new AuthenticationFailedException("Certificate with SN " + serno + " and issuerDN '" + issuerDN+ "' did not belong to any user in the database.");
            }
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            if (certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, serno) == null) {
                details.put("msg", "Logging in: Administrator Certificate is issued by external CA and not present in the database.");
            }
            if (WebConfiguration.getAdminLogRemoteAddress()) {
                details.put("remoteip", request.getRemoteAddr());
            }
            if (WebConfiguration.getAdminLogForwardedFor()) {
                details.put("forwardedip", StringTools.getCleanXForwardedFor(request.getHeader("X-Forwarded-For")));
            }
            // Also check if this administrator is present in any role, if not, login failed
            final List<String> roles = roleAccessSession.getRolesMatchingAuthenticationToken(administrator);
            if (roles.isEmpty()) {
                details.put("reason", "Certificate has no access");
                auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                        administrator.toString(), Integer.toString(issuerDN.hashCode()), sernostr, null, details);
                throw new AuthenticationFailedException("Authentication failed for certificate with no access: " + CertTools.getSubjectDN(certificates[0]));
            }
            // Continue with login
            if (details.isEmpty()) {
                details = null;
            }
            auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.SUCCESS, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                    administrator.toString(), Integer.toString(issuerDN.hashCode()), sernostr, null, details);
        }
        try {
            if (resources.length > 0 && !authorizationSession.isAuthorized(administrator, resources)) {
                throw new AuthorizationDeniedException("You are not authorized to view this page.");
            }
        } catch (EJBException e) {
            // Will this code ever execute? You are "initialized" (logged in) when the database went under
            // and your AppServer + JDBC driver throws an EJBException with SQLException as cause..?
            // Since the errorpage.jsp requires a database connection to show, it does not make any sense
            // to move this code there..
            final Throwable cause = e.getCause();
            if (cause instanceof SQLException || cause.getMessage().indexOf("SQLException", 0) >= 0) {
                throw new Exception(getText("DATABASEDOWN"), e);
            }
            throw e;
        }
        if (!initialized) {
            currentadminpreference = null;
            if (certificatefingerprint != null) {
                currentadminpreference = adminspreferences.getAdminPreference(certificatefingerprint);
            }
            if (currentadminpreference == null) {
                currentadminpreference = adminspreferences.getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                    currentadminpreference.getSecondaryLanguage());
            initialized = true;
        }

        return globalconfiguration;
    }

    /**
     * Method that returns the servername including port, extracted from the HTTPServlet Request, no protocol or application path is returned
     * 
     * @return the server name and port requested, i.e. localhost:8443
     */
    private String getRequestServerName(HttpServletRequest request) {
        String requestURL = request.getRequestURL().toString();
        // Remove https://
        requestURL = requestURL.substring(8);
        int firstSlash = requestURL.indexOf("/");
        // Remove application path
        requestURL = requestURL.substring(0, firstSlash);
        // Escape in order to be sure not to have any XSS
        requestURL = HTMLTools.htmlescape(requestURL);
        if (log.isDebugEnabled()) {
            log.debug("requestServerName: " + requestURL);
        }
        return requestURL;
    }

    public GlobalConfiguration initialize_errorpage(HttpServletRequest request) throws Exception {
        if (!errorpage_initialized) {
            if (administrator == null) {
                final String remoteAddr = request.getRemoteAddr();
                administrator = new AlwaysAllowLocalAuthenticationToken(new PublicWebPrincipal(remoteAddr));
            }
            commonInit();
            // Set ServletContext for reading language files from resources
            servletContext = request.getSession(true).getServletContext();
            if (currentadminpreference == null) {
                currentadminpreference = ejbLocalHelper.getRaAdminSession().getDefaultAdminPreference();
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

    /** Return the admins selected theme including its trailing '.css' */
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
    public boolean isAuthorized(String... resources) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(administrator, resources)) {
            throw new AuthorizationDeniedException("Not authorized to " + Arrays.toString(resources));
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
    public boolean isAuthorizedNoLog(String... resources) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(administrator, resources)) {
            throw new AuthorizationDeniedException("Not authorized to " + Arrays.toString(resources));
        }
        return true;
    }

    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Will simply return a boolean, 
     * no other information 
     * 
     * 
     * @return true if is authorized to resource, false if not
     */
    public boolean isAuthorizedNoLogSilent(String... resources) {
        return authorizationSession.isAuthorizedNoLogging(administrator, resources);
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
        if (raauthorized[resource] == null) {
            raauthorized[resource] = Boolean.valueOf(authorizationSession.isAuthorizedNoLogging(administrator, AUTHORIZED_RA_RESOURCES[resource]));
        }
        final boolean returnval = raauthorized[resource].booleanValue();
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
     * A functions that returns wanted helpfile in preferred language. The parameter helpfilename should the wanted filename without language infix.
     * For example: given helpfilename 'cahelp.html' would return 'cahelp.en.html' if English was the users preferred language.
     */
    public String getHelpfileInfix(String helpfilename) {
        String returnedurl = null;
        String[] strs = adminsweblanguage.getAvailableLanguages();
        int index = currentadminpreference.getPreferedLanguage();
        String prefered = strs[index];
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()];

        String helpfile = helpfilename.substring(0, helpfilename.lastIndexOf('.'));
        String postfix = helpfilename.substring(helpfilename.lastIndexOf('.') + 1);

        String preferedfilename = "/" + globalconfiguration.getHelpPath() + "/" + helpfile + "." + prefered + "." + postfix;

        String preferedurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" + helpfile + "."
                + prefered + "." + postfix;

        String secondaryurl = getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() + "/" + helpfile + "."
                + secondary + "." + postfix;

        try (InputStream stream = this.getClass().getResourceAsStream(preferedfilename)) {
            if (stream != null) {
                returnedurl = preferedurl;
            } else {
                returnedurl = secondaryurl;
            }
        } catch (IOException e) {
            log.info("IOException closing resource: ", e);
        }
        return returnedurl;
    }

    /**
     * A functions that returns wanted imagefile in preferred language and theme. If none of the language specific images are found the original
     * imagefilename will be returned.
     * 
     * The priority of filenames are in the following order 1. imagename.theme.preferedlanguage.png/jpg/gif 2. imagename.theme.secondarylanguage.png/jpg/gif
     * 3. imagename.theme.png/jpg/gif 4. imagename.preferedlanguage.png/jpg/gif 5. imagename.secondarylanguage.png/jpg/gif 6. imagename.png/jpg/gif
     * 
     * The parameter imagefilename should the wanted filename without language infix. For example: given imagefilename 'caimg.png' would return
     * 'caimg.en.png' if English was the users preferred language. It's important that all letters in imagefilename is lowercase.
     */

    public String getImagefileInfix(String imagefilename) {
        String returnedurl = null;
        String[] strs = adminsweblanguage.getAvailableLanguages();
        int index = currentadminpreference.getPreferedLanguage();
        String prefered = strs[index];
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()];

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

    public String[] getLanguagesEnglishNames() {
        return adminsweblanguage.getLanguagesEnglishNames();
    }

    public String[] getLanguagesNativeNames() {
        return adminsweblanguage.getLanguagesNativeNames();
    }

    public String getText(String template) {
        return adminsweblanguage.getText(template);
    }

    /**
     * @param template the entry in the language file to get
     * @param unescape true if html entities should be unescaped (&auml; converted to the real char)
     * @param params values of {0}, {1}, {2}... parameters
     * @return text string, possibly unescaped, or "template" if the template does not match any entry in the language files
     */
    public String getText(String template, boolean unescape, Object... params) {
        String str = adminsweblanguage.getText(template, params);
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

    public void reloadGlobalConfiguration() {
        globalconfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalconfiguration.initializeAdminWeb();
        if (informationmemory != null) {
            informationmemory.systemConfigurationEdited(globalconfiguration);
        }
    }
    
    public void saveGlobalConfiguration(GlobalConfiguration gc) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, gc);
        informationmemory.systemConfigurationEdited(gc);
        reloadGlobalConfiguration();
    }

    public void saveGlobalConfiguration() throws Exception {
        globalConfigurationSession.saveConfiguration(administrator, globalconfiguration);
        informationmemory.systemConfigurationEdited(globalconfiguration);
    }

    /**
     * Save the given CMP configuration.
     * 
     * @param cmpconfiguration A CMPConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    public void saveCmpConfiguration(CmpConfiguration cmpconfiguration) throws AuthorizationDeniedException {
        this.cmpconfiguration = cmpconfiguration;
        globalConfigurationSession.saveConfiguration(administrator, cmpconfiguration);
    }

    /**
     * Reload the current configuration from the database.
     */
    public void reloadCmpConfiguration() {
        cmpconfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    
    public boolean existsAdminPreference() {
        return adminspreferences.existsAdminPreference(certificatefingerprint);
    }

    public void addAdminPreference(AdminPreference ap) throws IOException, AdminExistsException {
        currentadminpreference = ap;
        adminspreferences.addAdminPreference(certificatefingerprint, ap);
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    public Collection<Integer> getAuthorizedCAIds() {
        return this.informationmemory.getAuthorizedCAIds();
    }

    public boolean isAuthorizedToAllCAs() {
        return caSession.getAllCaIds().size() == getAuthorizedCAIds().size();
    }

    public void changeAdminPreference(AdminPreference ap) throws AdminDoesntExistException {
        currentadminpreference = ap;
        adminspreferences.changeAdminPreference(certificatefingerprint, ap);
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage(),
                currentadminpreference.getSecondaryLanguage());
    }

    public AdminPreference getDefaultAdminPreference() {
        return adminspreferences.getDefaultAdminPreference();
    }

    public void saveDefaultAdminPreference(AdminPreference dap) throws AuthorizationDeniedException {
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
        Collection<Integer> caids = caSession.getAuthorizedCaIds(administrator);
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

    public boolean isPostUpgradeRequired() {
        return upgradeSession.isPostUpgradeNeeded();
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
        String prefered = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getPreferedLanguage()];
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()];
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

    public String getExternalHelpReference(String linkPart) {
        if (!isHelpEnabled()) {
            return "";
        }
        return "[<a href=\"" + linkPart + "\" target=\"" + GlobalConfiguration.DOCWINDOW + "\" title=\"" + getText("OPENHELPSECTION") + "\" >?</a>]";
    }

    public String[] getCertSernoAndIssuerdn(String certdata) {
        final String[] ret = StringTools.parseCertData(certdata);
        if (log.isDebugEnabled()) {
            log.debug("getCertSernoAndIssuerdn: " + certdata + " -> " + (ret==null?"null":(ret[0] + "," + ret[1])));
        }
        return ret;
    }

    public String getCleanOption(String parameter, String[] validOptions) {
        for (int i = 0; i < validOptions.length; i++) {
            if (parameter.equals(validOptions[i])) {
                return parameter;
            }
        }
        throw new IllegalArgumentException("Parameter " + parameter + " not found among valid options.");
    }

    public void clearClusterCache(boolean excludeActiveCryptoTokens) throws CacheClearException {
        if (log.isTraceEnabled()) {
            log.trace(">clearClusterCache");
        }
        final Set<String> nodes = globalconfiguration.getNodesInCluster();
        final StringBuilder failedHosts = new StringBuilder();
        final StringBuilder succeededHost = new StringBuilder();
        for (final String host : nodes) {
            try {
                if (host != null) {
                    if (checkHost(host, excludeActiveCryptoTokens)) {
                        succeededHost.append(' ').append(host);
                    } else {
                        if (isLocalHost(host)) {
                            // If we are trying to clear the cache on this instance and failed,
                            // we give it another chance using 127.0.0.1 (which is allowed by default)
                            log.info("Failed to clear cache on local node using '" + host + "'. Will try with 'localhost'.");
                            if (checkHost("localhost", excludeActiveCryptoTokens)) {
                                succeededHost.append(' ').append(host);
                            } else {
                                failedHosts.append(' ').append(host);
                            }
                        } else {
                            failedHosts.append(' ').append(host);
                        }
                    }
                }
            } catch (IOException e) {
                failedHosts.append(' ').append(host);
            }
        }
        // Invalidate local GUI cache
        initialized = false;
        if (failedHosts.length() > 0) {
            throw new CacheClearException("Failed to clear cache on hosts (" + failedHosts.toString().substring(1) + "), but succeeded on (" + succeededHost.toString().substring(1)
                    + ").");
        }
        if (log.isTraceEnabled()) {
            log.trace("<clearClusterCache");
        }
    }

    /** Perform HTTP connection to the cluster nodes clear-cache Servlet 
     * @throws IOException if any of the external hosts couldn't be contacted
     */
    private boolean checkHost(String hostname, boolean excludeActiveCryptoTokens) throws IOException {
        // get http port of remote host, this requires that all cluster nodes uses the same public htt port
        final int pubport = WebConfiguration.getPublicHttpPort();
        final String requestUrl = "http://" + hostname + ":" + pubport + "/ejbca/clearcache?command=clearcaches&excludeactivects="
                + excludeActiveCryptoTokens;
        final URL url = new URL(requestUrl);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        if (log.isDebugEnabled()) {
            log.debug("Contacting host with url:" + requestUrl);
        }
        try {
            final int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return true;
            }
            log.info("Failed to clear caches for host: " + hostname + ", responseCode=" + responseCode);
        } catch (SocketException e) {
            log.info("Failed to clear caches for host: " + hostname + ", message=" + e.getMessage());
        } catch (IOException e) {
            log.info("Failed to clear caches for host: " + hostname + ", message=" + e.getMessage());
        }
        return false;
    }

    /** @return true if the provided hostname matches the name reported by the system for localhost */
    private boolean isLocalHost(final String hostname) {
        try {
            if (hostname.equals(InetAddress.getLocalHost().getHostName())) {
                return true;
            }
        } catch (UnknownHostException e) {
            log.error("Hostname could not be determined", e);
        }
        return false;
    }

    public EjbLocalHelper getEjb() {
        return ejbLocalHelper;
    }

    public EnterpriseEjbLocalHelper getEnterpriseEjb() {
        return enterpriseEjbLocalHelper;
    }

    //**********************
    //     CMP
    //**********************

    public CmpConfiguration getCmpConfiguration() {
        if (cmpconfiguration == null) {
            reloadCmpConfiguration();
        }
        //Clear CMP config of unauthorized aliases (aliases referring to CA, EEP or CPs that the current admin doesn't have access to)
        return clearCmpConfigurationFromUnauthorizedAliases(cmpconfiguration);
    }

    /** 
     * Returns a clone of the current CMPConfiguration containing only the given alias. Also caches the clone locally. 
     * 
     * @param alias a CMP config alias
     * @return a clone of the current CMPConfiguration containing only the given alias. Will return an alias with only default values if the CmpConfiguration doesn't
     *          contain that alias.
     */
    public CmpConfiguration getCmpConfigForEdit(String alias) {
        if (cmpConfigForEdit != null) {
            return cmpConfigForEdit;
        }
        reloadCmpConfiguration();
        cmpConfigForEdit = new CmpConfiguration();
        cmpConfigForEdit.setAliasList(new LinkedHashSet<String>());
        cmpConfigForEdit.addAlias(alias);
        for(String key : CmpConfiguration.getAllAliasKeys(alias)) {
            String value = cmpconfiguration.getValue(key, alias);
            cmpConfigForEdit.setValue(key, value, alias);
        }
        return cmpConfigForEdit;
    }
    
    /**
     * Merges together an alias from the editing clone into the proper configuration cache and saves it to the database.
     * 
     * @param alias a CMP config alias. 
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void updateCmpConfigFromClone(String alias) throws AuthorizationDeniedException {
        if (cmpconfiguration.aliasExists(alias) && cmpConfigForEdit.aliasExists(alias)) {
            for(String key : CmpConfiguration.getAllAliasKeys(alias)) {
                String value = cmpConfigForEdit.getValue(key, alias);
                cmpconfiguration.setValue(key, value, alias);
            }
        }
        saveCmpConfiguration(cmpconfiguration);
    }

    /**
     * Adds an alias to the database.
     * 
     * @param alias the name of a CMP alias. 
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void addCmpAlias(final String alias) throws AuthorizationDeniedException {
        cmpconfiguration.addAlias(alias);
        saveCmpConfiguration(cmpconfiguration);
    }
    
    /**
     * Makes a copy of a given alias
     * 
     * @param oldName the name of the alias to copy
     * @param newName the name of the new alias
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void cloneCmpAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        cmpconfiguration.cloneAlias(oldName, newName);
        saveCmpConfiguration(cmpconfiguration);
    }
    
    /**
     * Deletes a CMP alias from the database.
     * 
     * @param alias the name of the alias to delete.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void removeCmpAlias(final String alias) throws AuthorizationDeniedException {
        cmpconfiguration.removeAlias(alias);
        saveCmpConfiguration(cmpconfiguration);
    }
    
    /**
     * Renames a CMP alias
     * 
     * @param oldName the old alias name
     * @param newName the new alias name
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void renameCmpAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        cmpconfiguration.renameAlias(oldName, newName);
        saveCmpConfiguration(cmpconfiguration);
    }
    
    public void clearCmpConfigClone() {
        cmpConfigForEdit = null;
    }

    public void clearCmpCache() {
        globalConfigurationSession.flushConfigurationCache(CmpConfiguration.CMP_CONFIGURATION_ID);
        reloadCmpConfiguration();
    }
    
    /**
     * 
     * Note that this method modifies the parameter, which is has to due to the design of UpgradableHashMap. 
     * 
     * @param cmpConfiguration the full CMP configuration
     * @return the modified cmpConfiguration, same as the parameter. 
     */
    private CmpConfiguration clearCmpConfigurationFromUnauthorizedAliases(final CmpConfiguration cmpConfiguration) {
        //Copy the configuration, because modifying parameters is nasty
        CmpConfiguration returnValue = new CmpConfiguration(cmpConfiguration);
        //Build a lookup map due to the fact that default CA is stored as a SubjectDNs 
        Map<String, String> subjectDnToCaNameMap = new HashMap<String, String>();
        for(int caId : caSession.getAllCaIds()) {           
            try {
                CAInfo caInfo = caSession.getCAInfoInternal(caId);
                subjectDnToCaNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("Newly retrieved CA not found.", e);
            }
            
        }
        Set<Integer> authorizedProfileIds = new HashSet<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator, ""));
        //Exclude all aliases which refer to CAs that current admin doesn't have access to
        aliasloop: for (String alias : new ArrayList<>(cmpConfiguration.getAliasList())) {
            //Collect CA names
            Set<String> caNames = new HashSet<>();
            String defaultCaSubjectDn = cmpConfiguration.getCMPDefaultCA(alias);
            if (!StringUtils.isEmpty(defaultCaSubjectDn)) {
                caNames.add(subjectDnToCaNameMap.get(defaultCaSubjectDn));
            }
            if (cmpConfiguration.getRAMode(alias)) {
                String authenticationCa = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, alias);
                if (!StringUtils.isEmpty(authenticationCa)) {
                    caNames.add(authenticationCa);
                }
                final String raCaName = cmpconfiguration.getRACAName(alias);
                if (!"ProfileDefault".equals(raCaName)) {
                    // "ProfileDefault" is not a CA name and if the profile default is used, this will be implicitly checked be checking access to the EEP
                    caNames.add(raCaName);
                }
                String eeProfileIdString = cmpconfiguration.getRAEEProfile(alias);
                if (eeProfileIdString != null && endEntityProfileSession.getEndEntityProfile(Integer.valueOf(eeProfileIdString)) != null) {
                    if (!authorizedProfileIds.contains(Integer.valueOf(eeProfileIdString))) {
                        if (log.isDebugEnabled()) {
                            log.debug("CMP alias " + alias + " hidden because admin lacks access to a CA used in end entity profile with ID: "
                                    + eeProfileIdString);
                        }
                        returnValue.removeAlias(alias);
                        //Profile was not in the authorized list, skip out on this alias. 
                        continue aliasloop;
                    }
                }
                //Certificate Profiles are tested implicitly, since we can't choose any CP which isn't part of the EEP, and we can't choose the EEP if we don't have access to its CPs. 
            }
            TreeMap<String, Integer> caNameToIdMap = getInformationMemory().getAllCANames();
            for (String caName : caNames) {
                if(caName != null) { //CA might have been removed
                    Integer caId = caNameToIdMap.get(caName);
                    if (caId != null) {
                        if (!caSession.authorizedToCANoLogging(administrator, caId)) {
                            if (log.isDebugEnabled()) {
                                log.debug("CMP alias " + alias + " hidden because admin lacks access to CA rule: " + StandardRules.CAACCESS.resource()
                                        + caNameToIdMap.get(caName));
                            }
                            returnValue.removeAlias(alias);
                            //Our work here is done, skip to the next alias. 
                            continue aliasloop;
                        }
                    }
                }
            }
        }

        return returnValue;
    }
    
    public Map<String, Integer> getAuthorizedEEProfileNamesAndIds(final String endentityAccessRule) {
        return informationmemory.getAuthorizedEndEntityProfileNames(endentityAccessRule);
    }

    public Collection<String> getAvailableCAsOfEEProfile(int endEntityProfileId) throws NumberFormatException, CADoesntExistsException,
            AuthorizationDeniedException {

        
        EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
        if (endEntityProfile == null) {
            return new HashSet<String>();
        }

        Collection<String> caids = endEntityProfile.getAvailableCAs();
        Set<String> cas = new HashSet<String>();

        for(String caid : caids) {
            if (caid.equals("1")) {
                return informationmemory.getAllCANames().keySet();
            }
            CA ca = caSession.getCA(administrator, Integer.parseInt(caid));
            cas.add(ca.getName());
        }
        return cas;
    }

    public Collection<String> getAvailableCertProfilessOfEEProfile(int endEntityProfileId) {
        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
        if (profile == null) {
            return new HashSet<String>();
        }
        Collection<String> cpids =  profile.getAvailableCertificateProfileIds();
        Set<String> cps = new HashSet<String>();
        for(String cpid : cpids) {
            String cpname = certificateProfileSession.getCertificateProfileName(Integer.parseInt(cpid));
            cps.add(cpname);
        }
        return cps;
    }
    
    public TreeMap<String, Integer> getVendorCAOptions() throws CADoesntExistsException {
        if(EjbcaConfiguration.getIsInProductionMode()) {
            return informationmemory.getExternalCAs();
        } else {
            return (TreeMap<String, Integer>) informationmemory.getCANames();
        }
    }

    //*************************************************
    //      AvailableExtendedKeyUsagesConfigration
    //*************************************************

    public AvailableExtendedKeyUsagesConfiguration getAvailableExtendedKeyUsagesConfiguration() {
        if (availableExtendedKeyUsagesConfig == null) {
            reloadAvailableExtendedKeyUsagesConfiguration();
        }
        return availableExtendedKeyUsagesConfig;
    }

    public void reloadAvailableExtendedKeyUsagesConfiguration() {
        availableExtendedKeyUsagesConfig = (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        if (informationmemory != null) {
            informationmemory.availableExtendedKeyUsagesConfigEdited(availableExtendedKeyUsagesConfig);
        }
    }

    public void saveAvailableExtendedKeyUsagesConfiguration(AvailableExtendedKeyUsagesConfiguration ekuConfig) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, ekuConfig);
        availableExtendedKeyUsagesConfig = ekuConfig;
        informationmemory.availableExtendedKeyUsagesConfigEdited(availableExtendedKeyUsagesConfig);
    }

    //*****************************************************************
    //       AvailableCustomCertificateExtensionsConfiguration
    //*****************************************************************

    public AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsConfiguration() {
        if (availableCustomCertExtensionsConfig == null) {
            reloadAvailableCustomCertExtensionsConfiguration();
        }
        return availableCustomCertExtensionsConfig;
    }

    public void reloadAvailableCustomCertExtensionsConfiguration() {
        availableCustomCertExtensionsConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        if (informationmemory != null) {
            informationmemory.availableCustomCertExtensionsConfigEdited(availableCustomCertExtensionsConfig);
        }
    }

    public void saveAvailableCustomCertExtensionsConfiguration(AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, cceConfig);
        availableCustomCertExtensionsConfig = cceConfig;
        informationmemory.availableCustomCertExtensionsConfigEdited(availableCustomCertExtensionsConfig);
    }

    //*******************************
    //         Peer Connector
    //*******************************

    private Boolean peerConnectorPresent = null;

    /** @return true if the PeerConnectors GUI implementation is present. */
    public boolean isPeerConnectorPresent() {
        if (peerConnectorPresent == null) {
            try {
                Class.forName("org.ejbca.ui.web.admin.peerconnector.PeerConnectorsMBean");
                peerConnectorPresent = Boolean.TRUE;
            } catch (ClassNotFoundException e) {
                peerConnectorPresent = Boolean.FALSE;
            }
        }
        return peerConnectorPresent.booleanValue();
    }

}
