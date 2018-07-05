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
import java.io.Serializable;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;

import javax.ejb.EJBException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.EnterpriseEjbLocalHelper;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;

/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @version $Id$
 */
public class EjbcaWebBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(EjbcaWebBean.class);

    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private final EnterpriseEjbLocalHelper enterpriseEjbLocalHelper = new EnterpriseEjbLocalHelper();
    private final AdminPreferenceSessionLocal adminPreferenceSession = ejbLocalHelper.getAdminPreferenceSession();
    private final ApprovalProfileSessionLocal approvalProfileSession = ejbLocalHelper.getApprovalProfileSession();
    private final AuthorizationSessionLocal authorizationSession = ejbLocalHelper.getAuthorizationSession();
    private final CAAdminSessionLocal caAdminSession = ejbLocalHelper.getCaAdminSession();
    private final CaSessionLocal caSession = ejbLocalHelper.getCaSession();
    private final CertificateProfileSessionLocal certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
    private final CertificateStoreSessionLocal certificateStoreSession = ejbLocalHelper.getCertificateStoreSession();
    private final EndEntityManagementSessionLocal endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
    private final EndEntityProfileSessionLocal endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
    private final HardTokenSessionLocal hardTokenSession = ejbLocalHelper.getHardTokenSession();
    private final PublisherSessionLocal publisherSession = ejbLocalHelper.getPublisherSession();
    private final SecurityEventsLoggerSessionLocal auditSession = ejbLocalHelper.getSecurityEventsLoggerSession();
    private final RoleSessionLocal roleSession = ejbLocalHelper.getRoleSession();
    private final UpgradeSessionLocal upgradeSession = ejbLocalHelper.getUpgradeSession();
    private final GlobalConfigurationSessionLocal globalConfigurationSession = ejbLocalHelper.getGlobalConfigurationSession();
    private final WebAuthenticationProviderSessionLocal authenticationSession = ejbLocalHelper.getWebAuthenticationProviderSession();

    private AdminPreference currentAdminPreference;
    private GlobalConfiguration globalconfiguration;
    private CmpConfiguration cmpconfiguration = null;
    private CmpConfiguration cmpConfigForEdit = null;
    private EstConfiguration estconfiguration = null;
    private EstConfiguration estConfigForEdit = null;
    private AvailableExtendedKeyUsagesConfiguration availableExtendedKeyUsagesConfig = null;
    private AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = null;
    private ServletContext servletContext = null;
    private WebLanguages adminsweblanguage;
    private String usercommonname = "";
    private String certificateFingerprint; // Unique key to identify the admin in this session. Usually a hash of the admin's certificate
    private String authenticationTokenTlsSessionId; // Keep the currect TLS session ID so we can detect changes
    private boolean initialized = false;
    private boolean errorpage_initialized = false;
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
    }

    private X509Certificate getClientX509Certificate(final HttpServletRequest httpServletRequest) {
        final X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("javax.servlet.request.X509Certificate");
        return certificates == null || certificates.length==0 ? null : certificates[0];
    }

    private String getTlsSessionId(final HttpServletRequest httpServletRequest) {
        final String sslSessionIdServletsStandard;
        final Object sslSessionIdServletsStandardObject = httpServletRequest.getAttribute("javax.servlet.request.ssl_session_id");
        if (sslSessionIdServletsStandardObject!=null && sslSessionIdServletsStandardObject instanceof byte[]) {
            // Wildfly 9 stores the TLS sessions as a raw byte array. Convert it to a hex String.
            sslSessionIdServletsStandard = new String(Hex.encode((byte[]) sslSessionIdServletsStandardObject), StandardCharsets.UTF_8);
        } else {
            sslSessionIdServletsStandard = (String) sslSessionIdServletsStandardObject;
        }
        final String sslSessionIdJBoss7 = (String)httpServletRequest.getAttribute("javax.servlet.request.ssl_session");
        return sslSessionIdJBoss7==null ? sslSessionIdServletsStandard : sslSessionIdJBoss7;
    }

    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String... resources) throws Exception {
        // Get some variables so we can detect if the TLS session and/or TLS client certificate changes within this session
        final X509Certificate certificate = getClientX509Certificate(request);
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        final String currentTlsSessionId = getTlsSessionId(request);
        // Re-initialize if we are not initialized (new session) or if authentication parameters change within an existing session (TLS session ID or client certificate).
        // If authentication parameters change it can be an indication of session hijacking, which should be denied if we re-auth, or just session re-use in web browser such as what FireFox 57 seems to do even after browser re-start
        if (!initialized || !StringUtils.equals(authenticationTokenTlsSessionId, currentTlsSessionId) || !StringUtils.equals(fingerprint, certificateFingerprint)) {
            if (log.isDebugEnabled() && initialized) {
                // Only log this if we are not initialized, i.e. if we entered here because session authentication parameters changed
                log.debug("TLS session authentication changed withing the HTTP Session, re-authenticating admin. Old TLS session ID: "+authenticationTokenTlsSessionId+", new TLS session ID: "+currentTlsSessionId+", old cert fp: "+certificateFingerprint+", new cert fp: "+fingerprint);
            }
            final String requestURL = request.getRequestURL().toString();
            requestServerName = RequestHelper.getRequestServerName(requestURL);
            if (log.isDebugEnabled()) {
                log.debug("requestServerName: "+requestServerName);
            }
            if (WebConfiguration.getRequireAdminCertificate() && certificate == null) {
                throw new AuthenticationFailedException("Client certificate required.");
            }
            if (certificate != null) {
                administrator = authenticationSession.authenticateUsingClientCertificate(certificate);
                if (administrator == null) {
                    throw new AuthenticationFailedException("Authentication failed for certificate: " + CertTools.getSubjectDN(certificate));
                }
                // Check if certificate and user is an RA Admin
                final String userdn = CertTools.getSubjectDN(certificate);
                final DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
                usercommonname = dn.getField(DNFieldExtractor.CN, 0);
                if (log.isDebugEnabled()) {
                    log.debug("Verifying authorization of '" + userdn + "'");
                }
                final String issuerDN = CertTools.getIssuerDN(certificate);
                final String sernostr = CertTools.getSerialNumberAsString(certificate);
                final BigInteger serno = CertTools.getSerialNumber(certificate);
                // Set current TLS certificate fingerprint
                certificateFingerprint = fingerprint;
                // Check if certificate belongs to a user. checkIfCertificateBelongToUser will always return true if WebConfiguration.getRequireAdminCertificateInDatabase is set to false (in properties file)
                if (!endEntityManagementSession.checkIfCertificateBelongToUser(serno, issuerDN)) {
                    throw new AuthenticationFailedException("Certificate with SN " + serno + " and issuerDN '" + issuerDN+ "' did not belong to any user in the database.");
                }
                Map<String, Object> details = new LinkedHashMap<>();
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
                if (roleSession.getRolesAuthenticationTokenIsMemberOf(administrator).isEmpty()) {
                    details.put("reason", "Certificate has no access");
                    auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                            administrator.toString(), Integer.toString(issuerDN.hashCode()), sernostr, null, details);
                    throw new AuthenticationFailedException("Authentication failed for certificate with no access: " + CertTools.getSubjectDN(certificate));
                }
                // Continue with login
                if (details.isEmpty()) {
                    details = null;
                }
                auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.SUCCESS, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                        administrator.toString(), Integer.toString(issuerDN.hashCode()), sernostr, null, details);
            } else {
                // TODO: When other types of authentication are implemented, check the distinct configured tokenTypes and try to authenticate for each
                administrator = authenticationSession.authenticateUsingNothing(request.getRemoteAddr(), currentTlsSessionId!=null);
                Map<String, Object> details = new LinkedHashMap<>();
                if (WebConfiguration.getAdminLogRemoteAddress()) {
                    details.put("remoteip", request.getRemoteAddr());
                }
                if (WebConfiguration.getAdminLogForwardedFor()) {
                    details.put("forwardedip", StringTools.getCleanXForwardedFor(request.getHeader("X-Forwarded-For")));
                }
                // Also check if this administrator is present in any role, if not, login failed
                if (roleSession.getRolesAuthenticationTokenIsMemberOf(administrator).isEmpty()) {
                    details.put("reason", "AuthenticationToken has no access");
                    auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                            administrator.toString(), null, null, null, details);
                    throw new AuthenticationFailedException("Authentication failed for certificate with no access: " + CertTools.getSubjectDN(certificate));
                }
                // Continue with login
                if (details.isEmpty()) {
                    details = null;
                }
                auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.SUCCESS, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                        administrator.toString(), null, null, null, details);
            }
            commonInit();
            // Set the current TLS session
            authenticationTokenTlsSessionId = currentTlsSessionId;
            // Set ServletContext for reading language files from resources
            servletContext = request.getSession(true).getServletContext();
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
            if ( cause instanceof SQLException || (cause.getMessage() != null && cause.getMessage().contains("SQLException")) ) {
                throw new Exception(getText("DATABASEDOWN"), e);
            }
            throw e;
        }
        if (!initialized) {
            currentAdminPreference = adminPreferenceSession.getAdminPreference(certificateFingerprint);
            if (currentAdminPreference == null) {
                currentAdminPreference = getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(), currentAdminPreference.getSecondaryLanguage());
            initialized = true;
        }

        return globalconfiguration;
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
            if (currentAdminPreference == null) {
                currentAdminPreference = getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(), currentAdminPreference.getSecondaryLanguage());
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
        return certificateFingerprint;
    }

    /** Return the admins selected theme including its trailing '.css' */
    public String getCssFile() {
        return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentAdminPreference.getTheme() + ".css";
    }

    /** Return the IE fixes CSS of the admins selected theme including it's trailing '.css' */
    public String getIeFixesCssFile() {
        return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentAdminPreference.getTheme()
                + globalconfiguration.getIeCssFilenamePostfix() + ".css";
    }

    /** Returns the admins prefered language */
    public int getPreferedLanguage() {
        return currentAdminPreference.getPreferedLanguage();
    }

    /** Returns the admins secondary language. */
    public int getSecondaryLanguage() {
        return currentAdminPreference.getSecondaryLanguage();
    }

    public int getEntriesPerPage() {
        return currentAdminPreference.getEntriesPerPage();
    }

    public int getLogEntriesPerPage() {
        return currentAdminPreference.getLogEntriesPerPage();
    }

    public void setLogEntriesPerPage(int logentriesperpage) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLogEntriesPerPage(logentriesperpage);
        saveCurrentAdminPreference();
    }

    public int getLastFilterMode() {
        return currentAdminPreference.getLastFilterMode();
    }

    public void setLastFilterMode(int lastfiltermode) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLastFilterMode(lastfiltermode);
        saveCurrentAdminPreference();
    }

    public int getLastLogFilterMode() {
        return currentAdminPreference.getLastLogFilterMode();
    }

    public void setLastLogFilterMode(int lastlogfiltermode) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLastLogFilterMode(lastlogfiltermode);
        saveCurrentAdminPreference();
    }

    public int getLastEndEntityProfile() {
        return currentAdminPreference.getLastProfile();
    }

    public void setLastEndEntityProfile(int lastprofile) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLastProfile(lastprofile);
        saveCurrentAdminPreference();
    }

    public boolean existsAdminPreference() {
        return adminPreferenceSession.existsAdminPreference(certificateFingerprint);
    }

    public void addAdminPreference(final AdminPreference adminPreference) throws AdminExistsException {
        currentAdminPreference = adminPreference;
        if (administrator instanceof X509CertificateAuthenticationToken) {
            if (!adminPreferenceSession.addAdminPreference((X509CertificateAuthenticationToken)administrator, adminPreference)) {
                throw new AdminExistsException("Admin already exists in the database.");
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    public void changeAdminPreference(AdminPreference adminPreference) throws AdminDoesntExistException {
        currentAdminPreference = adminPreference;
        if (administrator instanceof X509CertificateAuthenticationToken) {
            if (!adminPreferenceSession.changeAdminPreference((X509CertificateAuthenticationToken)administrator, adminPreference)) {
                throw new AdminDoesntExistException("Admin does not exist in the database.");
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    /** @return the current admin's preference */
    public AdminPreference getAdminPreference() {
        if (currentAdminPreference==null) {
            currentAdminPreference = adminPreferenceSession.getAdminPreference(certificateFingerprint);
            if (currentAdminPreference == null) {
                currentAdminPreference = getDefaultAdminPreference();
            }
        }
        return currentAdminPreference;
    }

    private void saveCurrentAdminPreference() throws AdminDoesntExistException, AdminExistsException {
        if (administrator instanceof X509CertificateAuthenticationToken) {
            if (existsAdminPreference()) {
                if (!adminPreferenceSession.changeAdminPreferenceNoLog((X509CertificateAuthenticationToken)administrator, currentAdminPreference)) {
                    throw new AdminDoesntExistException("Admin does not exist in the database.");
                }
            } else {
                if (!adminPreferenceSession.addAdminPreference((X509CertificateAuthenticationToken)administrator, currentAdminPreference)) {
                    throw new AdminExistsException("Admin already exists in the database.");
                }
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
    }
    
    public AdminPreference getDefaultAdminPreference() {
        return adminPreferenceSession.getDefaultAdminPreference();
    }
    
    public void saveDefaultAdminPreference(final AdminPreference adminPreference) throws AuthorizationDeniedException {
        adminPreferenceSession.saveDefaultAdminPreference(administrator, adminPreference);
        // Reload preferences
        currentAdminPreference = adminPreferenceSession.getAdminPreference(certificateFingerprint);
        if (currentAdminPreference == null) {
            currentAdminPreference = getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Used by menu page Does not return false if not
     * authorized, instead throws an AuthorizationDeniedException.
     *
     * @deprecated Don't use as is in a new admin GUI. Use {@link #isAuthorizedNoLogSilent(String...)} instead.
     *
     * @return true if is authorized to resource, throws AuthorizationDeniedException if not authorized, never returns false.
     * @throws AuthorizationDeniedException is not authorized to resource
     */
    @Deprecated
    public boolean isAuthorizedNoLog(String... resources) throws AuthorizationDeniedException { // still used by JSP code (viewcertificate.jsp and viewtoken.jsp)
        if (!authorizationSession.isAuthorizedNoLogging(administrator, resources)) {
            throw new AuthorizationDeniedException("Not authorized to " + Arrays.toString(resources));
        }
        return true;
    }

    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Will simply return a boolean,
     * does not throw exception.
     *
     * @return true if is authorized to resource, false if not
     */
    public boolean isAuthorizedNoLogSilent(String... resources) {
        return authorizationSession.isAuthorizedNoLogging(administrator, resources);
    }

    public String getBaseUrl() {
        return globalconfiguration.getBaseUrl(requestServerName);
    }

    public String getReportsPath() {
        return globalconfiguration.getReportsPath();
    }

    /* Returns the global configuration */
    public GlobalConfiguration getGlobalConfiguration() {
        return globalconfiguration;
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
        int index = currentAdminPreference.getPreferedLanguage();
        String prefered = strs[index];
        String secondary = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getSecondaryLanguage()];

        String imagefile = imagefilename.substring(0, imagefilename.lastIndexOf('.'));
        String theme = currentAdminPreference.getTheme().toLowerCase();
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
     * If the passed in value is empty, we return an empty string
     */
    public String getISO8601FromImpliedUTCOrRelative(final String dateString) {
        if (StringUtils.isEmpty(dateString)) {
            return "";
        }
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
    }

    public void saveGlobalConfiguration(GlobalConfiguration gc) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, gc);
        reloadGlobalConfiguration();
    }

    public void saveGlobalConfiguration() throws Exception {
        globalConfigurationSession.saveConfiguration(administrator, globalconfiguration);
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
     * Save the given EST configuration.
     *
     * @param estconfiguration A EstConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    public void saveEstConfiguration(EstConfiguration estconfiguration) throws AuthorizationDeniedException {
        this.estconfiguration = estconfiguration;
        globalConfigurationSession.saveConfiguration(administrator, estconfiguration);
    }

    /**
     * Reload the current configuration from the database.
     */
    public void reloadCmpConfiguration() {
        cmpconfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    public void reloadEstConfiguration() {
        estconfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
    }

    public TreeMap<String,Integer> getHardTokenProfiles() {
        final TreeMap<String,Integer> hardtokenprofiles = new TreeMap<>();
        for (Integer id : hardTokenSession.getAuthorizedHardTokenProfileIds(administrator)){
            final String name = hardTokenSession.getHardTokenProfileName(id.intValue());
            hardtokenprofiles.put(name, id);
        }
        return hardtokenprofiles;
    }

    public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers() {
        return hardTokenSession.getHardTokenIssuers(administrator);
    }

    public Map<Integer,String> getCAIdToNameMap() {
        return caSession.getCAIdToNameMap();
    }

    public List<Integer> getAuthorizedCAIds() {
        return caSession.getAuthorizedCaIds(administrator);
    }

    public TreeMap<String,Integer> getCANames() {
        return caSession.getAuthorizedCaNamesToIds(administrator);
    }

    public TreeMap<String,Integer> getExternalCANames() {
        TreeMap<String,Integer> ret = new TreeMap<>();
        for (CAInfo caInfo : caSession.getAuthorizedCaInfos(administrator)) {
            if (caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                ret.put(caInfo.getName(), caInfo.getCAId());
            }
        }
        return ret;
    }

    public TreeMap<String,Integer> getActiveCANames() {
        TreeMap<String, Integer> ret = new TreeMap<>();
        Map<Integer, String> idtonamemap = this.caSession.getActiveCAIdToNameMap(administrator);
        for (Integer id : idtonamemap.keySet()) {
            ret.put(idtonamemap.get(id), id);
        }
        return ret;
    }

    /** @return authorized CA Ids sorted by CA name alphabetically*/
    public Collection<Integer> getAuthorizedCAIdsByName() {
        return caSession.getAuthorizedCaNamesToIds(administrator).values();
    }

    public boolean isAuthorizedToAllCAs() {
        return caSession.getAllCaIds().size() == getAuthorizedCAIds().size();
    }

    public String getCertificateProfileName(final int profileId) {
        return certificateProfileSession.getCertificateProfileName(profileId);
    }

    /**
     * Returns authorized end entity  profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds;
        if (globalconfiguration.getIssueHardwareTokens()) {
            authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, CertificateConstants.CERTTYPE_HARDTOKEN);
        } else {
            authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, CertificateConstants.CERTTYPE_ENDENTITY);
        }
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, CertificateConstants.CERTTYPE_SUBCA);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, CertificateConstants.CERTTYPE_ROOTCA);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    /**
     * Method returning the all available approval profiles id to name.
     *
     * @return the approvalprofiles-id-to-name-map (HashMap)
     */
    public Map<Integer, String> getApprovalProfileIdToNameMap() {
        Map<Integer, String> approvalProfileMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        approvalProfileMap.put(-1, getText("NONE"));
        return approvalProfileMap;
    }

    public List<Integer> getSortedApprovalProfileIds() {
        List<ApprovalProfile> sortedProfiles = new ArrayList<>(approvalProfileSession.getAllApprovalProfiles().values());
        Collections.sort(sortedProfiles);
        List<Integer> result = new ArrayList<>();
        result.add(-1);
        for(ApprovalProfile approvalProfile : sortedProfiles) {
            result.add(approvalProfile.getProfileId());
        }
        return result;
    }

    /**
     * Returns all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap<String, Integer> getAuthorizedPublisherNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final Map<Integer, String> idtonamemap = publisherSession.getPublisherIdToNameMap();
        for(Integer id : caAdminSession.getAuthorizedPublisherIds(administrator)) {
            ret.put(idtonamemap.get(id), id);
        }
        return ret;
    }

    /**
     * Method returning the all available publishers id to name.
     *
     * @return the publisheridtonamemap (HashMap) sorted by value
     */
    public Map<Integer, String> getPublisherIdToNameMapByValue() {
        final Map<Integer,String> publisheridtonamemap = publisherSession.getPublisherIdToNameMap();
        final List<Map.Entry<Integer, String>> publisherIdToNameMapList = new LinkedList<>(publisheridtonamemap.entrySet());
        Collections.sort(publisherIdToNameMapList, new Comparator<Map.Entry<Integer, String>>() {
            @Override
            public int compare(Map.Entry<Integer, String> o1, Map.Entry<Integer, String> o2) {
                if (o1 == null) { return o2 == null ? 0 : -1; }
                else if (o2 == null) { return 1; }
                return o1.getValue().compareToIgnoreCase(o2.getValue());
            }
        });
        Map<Integer, String> sortedMap = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> entry : publisherIdToNameMapList) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }
        return sortedMap;
    }

    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (String)
     */
    public TreeMap<String, String> getAuthorizedEndEntityProfileNames(final String endentityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        return raAuthorization.getAuthorizedEndEntityProfileNames(endentityAccessRule);
    }

    public AuthenticationToken getAdminObject() {
        return this.administrator;
    }

    /**
     * Method returning all CA ids with CMS service enabled
     */
    public Collection<Integer> getCAIdsWithCMSServiceActive() {
        ArrayList<Integer> retval = new ArrayList<>();
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
        String prefered = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getPreferedLanguage()];
        String secondary = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getSecondaryLanguage()];
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
        return !"disabled".equalsIgnoreCase(WebConfiguration.getDocBaseUri());
    }

    public String getHelpBaseURI() {
        String helpBaseURI = WebConfiguration.getDocBaseUri();
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
            // The below will print hosts starting with a blank (space), but it's worth it to not have to consider error handling if toString is empty
            throw new CacheClearException("Failed to clear cache on hosts (" + failedHosts.toString() + "), but succeeded on (" + succeededHost.toString() + ").");
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
        Map<String, String> subjectDnToCaNameMap = new HashMap<>();
        for (int caId : caSession.getAllCaIds()) {
            CAInfo caInfo = caSession.getCAInfoInternal(caId);
            if (caInfo != null) {
                subjectDnToCaNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
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
                // If value is set to KeyId we will not hide it, because it can be any EE profile
                if (!StringUtils.equals(CmpConfiguration.PROFILE_USE_KEYID, eeProfileIdString)) {
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
                }
                //Certificate Profiles are tested implicitly, since we can't choose any CP which isn't part of the EEP, and we can't choose the EEP if we don't have access to its CPs.
            }
            TreeMap<String, Integer> caNameToIdMap = caSession.getAuthorizedCaNamesToIds(administrator);
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

    /**
     * Retrieve a mapping between authorized end entity profile names and their ids which can be displayed in the GUI.
     * The returned map will contain an additional "KeyID" entry which allows the end user to specify the end entity
     * in the CMP request.
     * @param endEntityAccessRule the access rule used for authorization
     * @return a map {end entity profile name} => {end entity profile id} with authorized end entituy profiles
     */
    public Map<String, String> getAuthorizedEEProfileNamesAndIds(final String endEntityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        final TreeMap<String, String> authorizedEEProfileNamesAndIds = new TreeMap<>(
                raAuthorization.getAuthorizedEndEntityProfileNames(endEntityAccessRule));
        // Add KeyId option. If used, extract the EE profile name from the senderKID field of the CMP request.
        // Important to add KeyId entry to a fresh copy, since the "Add End Entity" page will try to load end
        // entity profiles from this map.
        authorizedEEProfileNamesAndIds.put(CmpConfiguration.PROFILE_USE_KEYID, CmpConfiguration.PROFILE_USE_KEYID);
        return authorizedEEProfileNamesAndIds;
    }

    public Map<String, String> getAuthorizedEEProfilesAndIdsNoKeyId(final String endEntityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        return new TreeMap<>(raAuthorization.getAuthorizedEndEntityProfileNames(endEntityAccessRule));
    }

    /**
     * Retrieve a collection of available certificate authority ids based on end entity profile id. The returned list may
     * contain an additional "KeyID" option which allows the end user to specify the CA in the CMP request.
     * @param endEntityProfileId the id of an end entity profile
     * @return a sorted list of certificate authorities for the specified end entity profile
     * @throws NumberFormatException if the end entity profile id is not a number
     * @throws CADoesntExistsException if the certificate authority pointed to by an end entity profile does not exist
     * @throws AuthorizationDeniedException if we were denied access control
     */
    public Collection<String> getAvailableCAsOfEEProfile(final String endEntityProfileId)
            throws NumberFormatException, CADoesntExistsException, AuthorizationDeniedException {
        if (StringUtils.equals(endEntityProfileId, CmpConfiguration.PROFILE_USE_KEYID)) {
            final List<String> certificateAuthorities = new ArrayList<>(getCANames().keySet());
            return addKeyIdAndSort(certificateAuthorities);
        }
        final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(Integer.valueOf(endEntityProfileId));
        if (endEntityProfile == null) {
            return Collections.emptyList();
        }
        final Collection<Integer> certificateAuthorityIds = endEntityProfile.getAvailableCAs();
        if (certificateAuthorityIds.contains(CAConstants.ALLCAS)) {
            // End entity contains "Any CA"
            final List<String> certificateAuthorities = new ArrayList<>(getCANames().keySet());
            return addKeyIdAndSort(certificateAuthorities);
        }
        final List<String> certificateAuthorities = new ArrayList<>();
        for (final int id : certificateAuthorityIds) {
            final CA ca = caSession.getCANoLog(administrator, id);
            certificateAuthorities.add(ca.getName());
        }
        return addKeyIdAndSort(certificateAuthorities);
    }

    /**
     * Retrieve a list of certificate profile ids based on an end entity profile id. The returned list may contain
     * an additional "KeyID" option which allows the end user to specify the certificate profile in the CMP request.
     * @param endEntityProfileId the end entity profile id for which we want to fetch certificate profiles
     * @return a sorted list of certificate profile names
     */
    public Collection<String> getAvailableCertProfilesOfEEProfile(final String endEntityProfileId) {
        if (StringUtils.equals(endEntityProfileId, CmpConfiguration.PROFILE_USE_KEYID)) {
            final List<Integer> allCertificateProfileIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, 0);
            final List<String> allCertificateProfiles = new ArrayList<>(allCertificateProfileIds.size());
            for (final int id : allCertificateProfileIds) {
                allCertificateProfiles.add(certificateProfileSession.getCertificateProfileName(id));
            }
            return addKeyIdAndSort(allCertificateProfiles);
        }
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(Integer.valueOf(endEntityProfileId));
        if (profile == null) {
            return Collections.emptyList();
        }
        final Collection<Integer> certificateProfileIds = profile.getAvailableCertificateProfileIds();
        final List<String> certificateProfiles = new ArrayList<>();
        for (final int id : certificateProfileIds) {
            final String certificateProfile = certificateProfileSession.getCertificateProfileName(id);
            certificateProfiles.add(certificateProfile);
        }
        return addKeyIdAndSort(certificateProfiles);
    }

    private Collection<String> getAvailableCertProfileIDsOfEEProfileNoKeyID(final String endEntityProfileId) {
        if (StringUtils.equals(endEntityProfileId, CmpConfiguration.PROFILE_USE_KEYID)) {
            final List<Integer> allCertificateProfileIds = certificateProfileSession.getAuthorizedCertificateProfileIds(administrator, 0);
            final List<String> allCertificateProfiles = new ArrayList<>(allCertificateProfileIds.size());
            for (final int id : allCertificateProfileIds) {
                allCertificateProfiles.add(certificateProfileSession.getCertificateProfileName(id));
            }
            return allCertificateProfiles;
        }
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(Integer.valueOf(endEntityProfileId));
        if (profile == null) {
            return Collections.emptyList();
        }
        final Collection<String> certificateProfileIds = profile.getAvailableCertificateProfileIdsAsStrings();
        return certificateProfileIds;
    }

    /**
     * Retrieve a mapping between certificate profiles names and IDs available in the end entity profile. To be displayed in the GUI.
     * @param endEntityProfileId the the end entity profile in which we want to find certificate profiles
     * @return a map (TreeMap so it's sorted by key) {certificate profile name, certificate profile id} with authorized certificate profiles
     */
    public Map<String, String> getCertificateProfilesNoKeyId(final String endEntityProfileId) {
        final Map<Integer, String> map = certificateProfileSession.getCertificateProfileIdToNameMap();
        final TreeMap<String, String> certificateProfiles = new TreeMap<>();
        final Collection<String> ids = getAvailableCertProfileIDsOfEEProfileNoKeyID(endEntityProfileId);
        for (String idstr : ids) {
            certificateProfiles.put(map.get(Integer.valueOf(idstr)), idstr);
        }
        return certificateProfiles;
    }

    public Collection<String> getCertificateProfileIDsNoKeyId(final String endEntityProfileId) {
        final Collection<String> certificateProfiles = getAvailableCertProfilesOfEEProfile(endEntityProfileId);
        certificateProfiles.remove(CmpConfiguration.PROFILE_USE_KEYID);
        return certificateProfiles;
    }

    private Collection<String> addKeyIdAndSort(final List<String> entries) {
        // No point in adding KeyId if there are no options to choose from
        if (entries.size() > 1) {
            entries.add(CmpConfiguration.PROFILE_USE_KEYID);
        }
        Collections.sort(entries);
        return entries;
    }

    public TreeMap<String, Integer> getCAOptions() {
        return getCANames();
    }

    /**
     * Gets the list of CA names by the list of CA IDs.
     * @param idString the semicolon separated list of CA IDs.
     * @return the list of CA names as semicolon separated String.
     * @throws NumberFormatException if a CA ID could not be parsed.
     * @throws AuthorizationDeniedException if authorization was denied.
     */
    public String getCaNamesString(final String idString) throws NumberFormatException, AuthorizationDeniedException {
        final TreeMap<String, Integer> availableCas = getCAOptions();
        final List<String> result = new ArrayList<>();
        if (StringUtils.isNotBlank(idString)) {
            for (String id : idString.split(";")) {
                if (availableCas.containsValue(Integer.valueOf(id))) {
                    for (Entry<String,Integer> entry : availableCas.entrySet()) {
                        if (entry.getValue() != null && entry.getValue().equals( Integer.valueOf(id))) {
                            result.add(entry.getKey());
                        }
                    }
                }
            }
        }
        return StringUtils.join(result, ";");
    }


    //**********************
    //     EST
    //**********************

    /** @return true if the EST implementation is present. */
    public boolean isEstConfigurationPresent() {
        return enterpriseEjbLocalHelper.isRunningEnterprise();
    }
    
    public boolean isRestConfigurationPresent() {
        return enterpriseEjbLocalHelper.isRunningEnterprise();
    }

    public boolean isAcmeConfigurationPresent() {
        return enterpriseEjbLocalHelper.isRunningEnterprise();
    }

    public EstConfiguration getEstConfiguration() {
        if (estconfiguration == null) {
            reloadEstConfiguration();
        }

        //Clear EST config of unauthorized aliases (aliases referring to CA, EEP or CPs that the current admin doesn't have access to)
        return clearEstConfigurationFromUnauthorizedAliases(estconfiguration);
    }

    /**
     * Returns a clone of the current EstConfiguration containing only the given alias. Also caches the clone locally.
     *
     * @param alias a EST config alias
     * @return a clone of the current EstConfiguration containing only the given alias. Will return an alias with only default values if the EstConfiguration doesn't
     *          contain that alias.
     */
    public EstConfiguration getEstConfigForEdit(String alias) {
        if (estConfigForEdit != null) {
            return estConfigForEdit;
        }
        reloadEstConfiguration();
        estConfigForEdit = new EstConfiguration();
        estConfigForEdit.setAliasList(new LinkedHashSet<String>());
        estConfigForEdit.addAlias(alias);
        for(String key : EstConfiguration.getAllAliasKeys(alias)) {
            String value = estconfiguration.getValue(key, alias);
            estConfigForEdit.setValue(key, value, alias);
        }
        return estConfigForEdit;
    }

    /**
     * Merges together an alias from the editing clone into the proper configuration cache and saves it to the database.
     *
     * @param alias a EST config alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void updateEstConfigFromClone(String alias) throws AuthorizationDeniedException {
        if (estconfiguration.aliasExists(alias) && estConfigForEdit.aliasExists(alias)) {
            for(String key : EstConfiguration.getAllAliasKeys(alias)) {
                String value = estConfigForEdit.getValue(key, alias);
                estconfiguration.setValue(key, value, alias);
            }
        }
        saveEstConfiguration(estconfiguration);
    }

    /**
     * Adds an alias to the database.
     *
     * @param alias the name of a EST alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void addEstAlias(final String alias) throws AuthorizationDeniedException {
        estconfiguration.addAlias(alias);
        saveEstConfiguration(estconfiguration);
    }

    /**
     * Makes a copy of a given alias
     *
     * @param oldName the name of the alias to copy
     * @param newName the name of the new alias
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void cloneEstAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        estconfiguration.cloneAlias(oldName, newName);
        saveEstConfiguration(estconfiguration);
    }

    /**
     * Deletes a EST alias from the database.
     *
     * @param alias the name of the alias to delete.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void removeEstAlias(final String alias) throws AuthorizationDeniedException {
        estconfiguration.removeAlias(alias);
        saveEstConfiguration(estconfiguration);
    }

    /**
     * Renames a EST alias
     *
     * @param oldName the old alias name
     * @param newName the new alias name
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    public void renameEstAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        estconfiguration.renameAlias(oldName, newName);
        saveEstConfiguration(estconfiguration);
    }

    public void clearEstConfigClone() {
        estConfigForEdit = null;
    }

    public void clearEstCache() {
        globalConfigurationSession.flushConfigurationCache(EstConfiguration.EST_CONFIGURATION_ID);
        reloadEstConfiguration();
    }

    /**
     * Removes EST aliases where the administrator does not have permissions to CA set as defaultCA
     * Note that this method modifies the parameter, which is has to due to the design of UpgradableHashMap.
     *
     * @param estConfiguration the full CMP configuration
     * @return the modified estConfiguration, same as the parameter.
     */
    private EstConfiguration clearEstConfigurationFromUnauthorizedAliases(final EstConfiguration estConfiguration) {
        //Copy the configuration, because modifying parameters is nasty
        EstConfiguration returnValue = new EstConfiguration(estConfiguration);
        //Exclude all aliases which refer to CAs that current admin doesn't have access to
        aliasloop: for (String alias : new ArrayList<>(estConfiguration.getAliasList())) {
            Integer caId = 0;
            // To be backward compatible with EJBCA 6.11, where this was stored as the name instead of ID, we make it possible to use both. See ECA-6556
            String defaultCAIDStr = estConfiguration.getDefaultCAID(alias);
            if (NumberUtils.isNumber(defaultCAIDStr)) {
                caId = Integer.valueOf(defaultCAIDStr);
            } else {
                // We have a caName, and want the Id
                CAInfo cainfo = caSession.getCAInfoInternal(-1, defaultCAIDStr, true);
                if (cainfo != null) {
                    caId = cainfo.getCAId();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("CA with name '"+defaultCAIDStr+"' does not exist, allowing everyone to view EST alias '"+alias+"'.");
                    }
                }
            }
            if (caId != 0) {
                if (!caSession.authorizedToCANoLogging(administrator, caId)) {
                    if (log.isDebugEnabled()) {
                        log.debug("EST alias " + alias + " hidden because admin lacks access to CA rule: " + StandardRules.CAACCESS.resource() + caId);
                    }
                    returnValue.removeAlias(alias);
                    //Our work here is done, skip to the next alias.
                    continue aliasloop;
                }
            }
        }
        return returnValue;
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
    }

    public void saveAvailableExtendedKeyUsagesConfiguration(AvailableExtendedKeyUsagesConfiguration ekuConfig) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, ekuConfig);
        availableExtendedKeyUsagesConfig = ekuConfig;
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
    }

    public void saveAvailableCustomCertExtensionsConfiguration(AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(administrator, cceConfig);
        availableCustomCertExtensionsConfig = cceConfig;
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
