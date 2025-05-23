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
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.stream.Collectors;

import jakarta.ejb.EJBException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.AuthenticationNotProvidedException;
import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.EABConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.LogRedactionUtils;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.ClearCacheSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.EnterpriseEjbLocalHelper;
import org.ejbca.ui.web.StaticResourceVersioning;
import org.ejbca.ui.web.configuration.WebLanguage;
import org.ejbca.ui.web.configuration.exception.AdminDoesntExistException;
import org.ejbca.ui.web.configuration.exception.AdminExistsException;
import org.ejbca.ui.web.configuration.exception.CacheClearException;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.HTMLTools;
import org.ejbca.util.HttpTools;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.keys.KeyTools;

import static org.ejbca.core.ejb.authorization.AuthorizationSystemSession.SUPERADMIN_ROLE;
import static org.primefaces.util.Constants.SEMICOLON;

/**
 * The main bean for the web interface, it contains all basic functions.
 * <p>
 * Do not add page specific code here, use a ManagedBean for that.
 * </p>
 */
public class EjbcaWebBeanImpl implements EjbcaWebBean {

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(EjbcaWebBeanImpl.class);

    private static final char SINGLE_SPACE_CHAR = ' ';
    private static final String PUBLIC_ACCESS_AUTHENTICATION_TOKEN = "PublicAccessAuthenticationToken";

    private final EjbBridgeSessionLocal ejbLocalHelper;
    private final EnterpriseEditionEjbBridgeSessionLocal enterpriseEjbLocalHelper;
    private final AdminPreferenceSessionLocal adminPreferenceSession;
    private final ApprovalProfileSessionLocal approvalProfileSession;
    private final AuthorizationSessionLocal authorizationSession;
    private final CAAdminSessionLocal caAdminSession;
    private final CaSessionLocal caSession;
    private final CertificateProfileSessionLocal certificateProfileSession;
    private final CertificateStoreSessionLocal certificateStoreSession;
    private final EndEntityManagementSessionLocal endEntityManagementSession;
    private final EndEntityProfileSessionLocal endEntityProfileSession;
    private final PublisherSessionLocal publisherSession;
    private final SecurityEventsLoggerSessionLocal auditSession;
    private final RoleSessionLocal roleSession;
    private final RoleMemberSessionLocal roleMemberSession;
    private final UpgradeSessionLocal upgradeSession;
    private final GlobalConfigurationSessionLocal globalConfigurationSession;
    private final WebAuthenticationProviderSessionLocal authenticationSession;
    private final ClearCacheSessionLocal clearCacheSession;

    private AdminPreference currentAdminPreference;
    private GlobalConfiguration globalconfiguration;
    private CmpConfiguration cmpconfiguration = null;
    private CmpConfiguration cmpConfigForEdit = null;
    private EstConfiguration estconfiguration = null;
    private EstConfiguration estConfigForEdit = null;
    private MSAutoEnrollmentConfiguration msAutoenrollmentConfig = null;
    private MSAutoEnrollmentConfiguration msAutoenrollmentConfigForEdit = null;
    private AvailableExtendedKeyUsagesConfiguration availableExtendedKeyUsagesConfig = null;
    private AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = null;
    private OAuthConfiguration oAuthConfiguration = null;
    private EABConfiguration eabConfiguration = null;
    private ServletContext servletContext = null;
    private WebLanguagesImpl adminsweblanguage;

    /** Wraps all authentication state, so it can be replaced atomically (i.e. other threads won't see "half-updated" state) */
    private class AuthState {
        String usercommonname = "";
        String certificateFingerprint; // Unique key to identify the admin in this session. Usually a hash of the admin's certificate
        String authenticationTokenTlsSessionId; // Keep the currect TLS session ID so we can detect changes
        boolean isAuthenticatedWithToken; // a flag to detect authentication path used
        String oauthAuthenticationToken; // Keep token used for authentication so we can detect changes
        String oauthIdToken;
        boolean initialized = false;
        boolean errorpage_initialized = false;
        AuthenticationToken administrator;
        String requestServerName;
        String currentRemoteIp;
    }

    private AuthState authState = new AuthState();
    private AuthState stagingState = new AuthState();

    /*
     * We should make this configurable, so GUI client can use their own time zone rather than the
     * servers. Using JavaScript's "new Date().getTimezoneOffset()" in a cookie will not work on
     * the first load of the GUI, so a configurable parameter in the user's preferences is probably
     * the way to go.
     */
    private final TimeZone timeZone = ValidityDate.TIMEZONE_SERVER;

    /** Creates a new instance of EjbcaWebBeanImpl */
    public EjbcaWebBeanImpl() {
        this(new EjbLocalHelper(), new EnterpriseEjbLocalHelper());
    }

    /** Constructor for unit testing with mock objects */
    protected EjbcaWebBeanImpl(final EjbBridgeSessionLocal ejbBridge, final EnterpriseEditionEjbBridgeSessionLocal enterpriseEjbBridge) {
        ejbLocalHelper = ejbBridge;
        enterpriseEjbLocalHelper = enterpriseEjbBridge;
        adminPreferenceSession = ejbLocalHelper.getAdminPreferenceSession();
        approvalProfileSession = ejbLocalHelper.getApprovalProfileSession();
        authorizationSession = ejbLocalHelper.getAuthorizationSession();
        caAdminSession = ejbLocalHelper.getCaAdminSession();
        caSession = ejbLocalHelper.getCaSession();
        certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
        certificateStoreSession = ejbLocalHelper.getCertificateStoreSession();
        endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
        endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
        publisherSession = ejbLocalHelper.getPublisherSession();
        auditSession = ejbLocalHelper.getSecurityEventsLoggerSession();
        roleSession = ejbLocalHelper.getRoleSession();
        roleMemberSession = ejbLocalHelper.getRoleMemberSession();
        upgradeSession = ejbLocalHelper.getUpgradeSession();
        globalConfigurationSession = ejbLocalHelper.getGlobalConfigurationSession();
        authenticationSession = ejbLocalHelper.getWebAuthenticationProviderSession();
        clearCacheSession = ejbLocalHelper.getClearCacheSession();
    }

    private void commonInit() {
        reloadGlobalConfiguration();
        reloadCmpConfiguration();
        reloadAvailableExtendedKeyUsagesConfiguration();
        reloadAvailableCustomCertExtensionsConfiguration();
    }

    @Override
    public X509Certificate getClientX509Certificate(final HttpServletRequest httpServletRequest) {
        final X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("jakarta.servlet.request.X509Certificate");
        return certificates == null || certificates.length==0 ? null : certificates[0];
    }

    private String getTlsSessionId(final HttpServletRequest httpServletRequest) {
        final String sslSessionIdServletsStandard;
        final Object sslSessionIdServletsStandardObject = httpServletRequest.getAttribute("jakarta.servlet.request.ssl_session_id");
        if (sslSessionIdServletsStandardObject!=null && sslSessionIdServletsStandardObject instanceof byte[]) {
            // Wildfly 9 stores the TLS sessions as a raw byte array. Convert it to a hex String.
            sslSessionIdServletsStandard = new String(Hex.encode((byte[]) sslSessionIdServletsStandardObject), StandardCharsets.UTF_8);
        } else {
            sslSessionIdServletsStandard = (String) sslSessionIdServletsStandardObject;
        }
        final String sslSessionIdJBoss7 = (String)httpServletRequest.getAttribute("javax.servlet.request.ssl_session");
        return sslSessionIdJBoss7==null ? sslSessionIdServletsStandard : sslSessionIdJBoss7;
    }

    @Override
    public synchronized GlobalConfiguration initialize(final HttpServletRequest httpServletRequest, final String... resources) throws Exception {
        try {
            stagingState = new AuthState();
            return initializeInternal(httpServletRequest, resources);
        } finally {
            if (!stagingState.initialized && !stagingState.errorpage_initialized) {
                // Make sure we at least have the needed information (default language strings etc.) to show an error page
                initializeErrorPageInternal(httpServletRequest);
            }
            authState = stagingState;
            stagingState = new AuthState(); // make sure any half-initialized state is never used
        }
    }

    /** Sets the current user and returns the global configuration */
    private GlobalConfiguration initializeInternal(final HttpServletRequest httpServletRequest, final String... resources) throws Exception {
        // Get some variables so we can detect if the TLS session and/or TLS client certificate changes within this session
        final X509Certificate certificate = getClientX509Certificate(httpServletRequest);
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        final String currentTlsSessionId = getTlsSessionId(httpServletRequest);
        final String oauthBearerToken = getBearerToken(httpServletRequest);
        final String oauthIdToken = getOauthIdToken(httpServletRequest);
        // Re-initialize if we are not initialized (new session) or if authentication parameters change within an existing session (TLS session ID or client certificate).
        // If authentication parameters change it can be an indication of session hijacking, which should be denied if we re-auth, or just session re-use in web browser such as what FireFox 57 seems to do even after browser re-start
        if (!authState.initialized || !StringUtils.equals(authState.authenticationTokenTlsSessionId, currentTlsSessionId)
                || (authState.isAuthenticatedWithToken && !StringUtils.equals(authState.oauthAuthenticationToken, oauthBearerToken))
                || (authState.isAuthenticatedWithToken && !StringUtils.equals(authState.oauthIdToken, oauthIdToken))
                || (!authState.isAuthenticatedWithToken && !StringUtils.equals(fingerprint, authState.certificateFingerprint))) {
            if (log.isDebugEnabled() && authState.initialized) {
                // Only log this if we are not initialized, i.e. if we entered here because session authentication parameters changed
                log.debug("TLS session authentication changed withing the HTTP Session, re-authenticating admin. Old TLS session ID: "+authState.authenticationTokenTlsSessionId+", new TLS session ID: "+currentTlsSessionId+", old cert fp: "+authState.certificateFingerprint+", new cert fp: "+fingerprint);
            }
            // Escape value taken from the request, just to be sure there can be no XSS
            HTMLTools.htmlescape(httpServletRequest.getScheme());
            stagingState.requestServerName = HTMLTools.htmlescape(httpServletRequest.getServerName());
            stagingState.currentRemoteIp = httpServletRequest.getRemoteAddr();
            if (log.isDebugEnabled()) {
                log.debug("requestServerName: "+stagingState.requestServerName);
            }
            if (WebConfiguration.isAdminAuthenticationRequired() && certificate == null && oauthBearerToken == null) {
                throw new AuthenticationNotProvidedException("Client certificate or OAuth bearer token required.");
            }
            if (certificate != null) {
                stagingState.administrator = authenticationSession.authenticateUsingClientCertificate(certificate);
                if (stagingState.administrator == null) {
                    if (oauthBearerToken == null) {
                        throw new AuthenticationFailedException("Authentication failed for certificate: " + CertTools.getSubjectDN(certificate));
                    } else {
                        log.info("Authentication failed for certificate: " + CertTools.getSubjectDN(certificate));
                    }
                } else {
                    // Check if certificate and user is an RA Admin
                    final String userdn = CertTools.getSubjectDN(certificate);
                    final DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
                    stagingState.usercommonname = dn.getField(DNFieldExtractor.CN, 0);
                    if (log.isDebugEnabled()) {
                        log.debug("Verifying authorization of '" + LogRedactionUtils.getSubjectDnLogSafe(userdn) + "'");
                    }
                    final String issuerDN = CertTools.getIssuerDN(certificate);
                    final String sernostr = CertTools.getSerialNumberAsString(certificate);
                    final BigInteger serno = CertTools.getSerialNumber(certificate);
                    // Set current TLS certificate fingerprint
                    stagingState.certificateFingerprint = fingerprint;
                    // Check if certificate belongs to a user. checkIfCertificateBelongToUser will always return true if WebConfiguration.getRequireAdminCertificateInDatabase is set to false (in properties file)
                    if (!endEntityManagementSession.checkIfCertificateBelongToUser(serno, issuerDN)) {
                        throw new AuthenticationFailedException("Certificate with SN " + serno + " and issuerDN '" + issuerDN + "' did not belong to any user in the database.");
                    }
                    final Map<String, Object> details = new LinkedHashMap<>();
                    if (certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, serno) == null) {
                        details.put("msg", "Logging in: Administrator Certificate is issued by external CA and not present in the database.");
                    }
                    if (!checkRoleMembershipAndLog(httpServletRequest, "Client certificate", issuerDN, sernostr, details)) {
                        if (oauthBearerToken == null) {
                            throw new AuthenticationFailedException("Authentication failed for certificate with no access: " + CertTools.getSubjectDN(certificate));
                        } else {
                            stagingState.administrator = null;
                            stagingState.certificateFingerprint = null;
                            log.info("Authentication failed for certificate with no access: " + CertTools.getSubjectDN(certificate));
                        }
                    }
                }
            }
            if (oauthBearerToken != null && stagingState.administrator == null) {
                try {
                    stagingState.administrator = authenticationSession.authenticateUsingOAuthBearerToken(getOAuthConfiguration(), oauthBearerToken, oauthIdToken);
                } catch (TokenExpiredException e) {
                    String refreshToken = getRefreshToken(httpServletRequest);
                    if (refreshToken != null) {
                        OAuthGrantResponseInfo token = authenticationSession.refreshOAuthBearerToken(getOAuthConfiguration(), oauthBearerToken, oauthIdToken, refreshToken);
                        if (token != null) {
                            httpServletRequest.getSession(true).setAttribute("ejbca.bearer.token", token.getAccessToken());
                            if (token.getIdToken() != null) {
                                httpServletRequest.getSession(true).setAttribute("ejbca.id.token", token.getIdToken());
                            }
                            if (token.getRefreshToken() != null) {
                                httpServletRequest.getSession(true).setAttribute("ejbca.refresh.token", token.getRefreshToken());
                            }
                            stagingState.administrator = authenticationSession.authenticateUsingOAuthBearerToken(getOAuthConfiguration(),
                                    token.getAccessToken(), token.getIdToken());
                        }
                    }
                }
                if (stagingState.administrator == null) {
                    throw new AuthenticationFailedException("Authentication failed using OAuth Bearer Token");
                }
                stagingState.isAuthenticatedWithToken = true;
                stagingState.oauthAuthenticationToken = oauthBearerToken;
                stagingState.oauthIdToken = oauthIdToken;
                final Map<String, Object> details = new LinkedHashMap<>();
                final OAuth2AuthenticationToken oauth2Admin = (OAuth2AuthenticationToken) stagingState.administrator;
                final OAuth2Principal principal = oauth2Admin.getClaims();
                details.put("keyhash", oauth2Admin.getPublicKeyBase64Fingerprint());
                putOauthTokenDetails(details, principal);
                if (oauth2Admin.getProviderLabel() != null) {
                    details.put("provider", oauth2Admin.getProviderLabel());
                }
                if (!checkRoleMembershipAndLog(httpServletRequest, "OAuth Bearer Token", null, principal.getSubject(), details)) {
                    throw new AuthenticationFailedException("Authentication failed for bearer token with no access: " + principal.getName());
                }
                stagingState.usercommonname = principal.getDisplayName();
            }
            if (stagingState.administrator == null) {
                stagingState.administrator = authenticationSession.authenticateUsingNothing(stagingState.currentRemoteIp, httpServletRequest.isSecure());
                final Map<String, Object> details = new LinkedHashMap<>();
                if (!checkRoleMembershipAndLog(httpServletRequest, "AuthenticationToken", null, null, details)) {
                    throw new AuthenticationFailedException("Authentication failed for certificate with no access");
                }
            }
            commonInit();
            // Set the current TLS session
            stagingState.authenticationTokenTlsSessionId = currentTlsSessionId;
            // Set ServletContext for reading language files from resources
            servletContext = httpServletRequest.getSession(true).getServletContext();
        } else {
            // No need to authenticate again
            stagingState = authState;
        }
        try {
            if (resources.length > 0 && !authorizationSession.isAuthorized(stagingState.administrator, resources)) {
                throw new AuthorizationDeniedException("You are not authorized to view this page.");
            }
        } catch (final EJBException e) {
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
        if (!stagingState.initialized) {
            currentAdminPreference = adminPreferenceSession.getAdminPreference(stagingState.administrator);
            if (currentAdminPreference == null) {
                currentAdminPreference = getDefaultAdminPreference();
            }
            adminsweblanguage = new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(), currentAdminPreference.getSecondaryLanguage());
            stagingState.initialized = true;
        }

        return globalconfiguration;
    }

    private void putOauthTokenDetails(final Map<String, Object> details, final OAuth2Principal principal) {
        if (principal.getIssuer() != null) {
            details.put("issuer", principal.getIssuer());
        }
        if (principal.getSubject() != null) {
            details.put("subject", principal.getSubject());
        }
        if (principal.getAudience() != null) {
            details.put("audience", Arrays.toString(principal.getAudience().toArray()));
        }
        if (principal.getPreferredUsername() != null) {
            details.put("preferred_username", principal.getPreferredUsername());
        }
        if (principal.getNameAttribute() != null) {
            details.put("name", principal.getNameAttribute());
        }
        if (principal.getEmail() != null) {
            details.put("email", principal.getEmail());
        }
    }

    /**
     * Gets bearer token from Authorization header or from session
     * @param httpServletRequest
     * @return
     */
    private String getBearerToken(HttpServletRequest httpServletRequest) {
        String oauthBearerToken = HttpTools.extractBearerAuthorization(httpServletRequest.getHeader(HttpTools.AUTHORIZATION_HEADER));
        if (oauthBearerToken == null) {
            oauthBearerToken = (String) httpServletRequest.getSession(true).getAttribute("ejbca.bearer.token");
        }
        return oauthBearerToken;
    }

    private String getOauthIdToken(final HttpServletRequest httpServletRequest) {
        final String oauthBearerToken = HttpTools.extractBearerAuthorization(httpServletRequest.getHeader(HttpTools.AUTHORIZATION_HEADER));
        if (oauthBearerToken != null) {
            // Can't mix an ID Token with an access token from an HTTP header (it would be insecure)
            return null;
        }
        return (String) httpServletRequest.getSession(true).getAttribute("ejbca.id.token");
    }

    /**
     * Gets refresh token from session
     * @param httpServletRequest
     * @return
     */
    private String getRefreshToken(HttpServletRequest httpServletRequest) {
            return  (String) httpServletRequest.getSession(true).getAttribute("ejbca.refresh.token");
    }

    /**
     * @param httpServletRequest
     * @param issuerDN Issuer DN, or null if not relevant for the authentication method.
     * @param searchDetail1 Authentication method specific data, such as a certificate serial number.
     * @param details Additional details to include in audit log record.
     * @return true on successful authentication, false on failure.
     */
    private boolean checkRoleMembershipAndLog(final HttpServletRequest httpServletRequest, final String tokenDescription, final String issuerDN,
            final String searchDetail1, Map<String, Object> details) {
        final String caIdString = issuerDN != null ? Integer.toString(issuerDN.hashCode()) : null;
        if (WebConfiguration.getAdminLogRemoteAddress()) {
            details.put("remoteip", stagingState.currentRemoteIp);
        }
        if (WebConfiguration.getAdminLogForwardedFor()) {
            details.put("forwardedip", StringTools.getCleanXForwardedFor(httpServletRequest.getHeader("X-Forwarded-For")));
        }
        // Also check if this administrator is present in any role, if not, login failed
        if (roleSession.getRolesAuthenticationTokenIsMemberOf(stagingState.administrator).isEmpty()) {
            details.put("reason", tokenDescription + " has no access");
            auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                    stagingState.administrator.toString(), caIdString, searchDetail1, null, details);
            return false;
        }
        // Continue with login
        if (details.isEmpty()) {
            details = null;
        }
        auditSession.log(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN, EventStatus.SUCCESS, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA,
                stagingState.administrator.toString(), caIdString, searchDetail1, null, details);
        return true;
    }

    @Override
    public synchronized GlobalConfiguration initialize_errorpage(final HttpServletRequest request) {
        if (!authState.errorpage_initialized) {
            stagingState = new AuthState();
            initializeErrorPageInternal(request);
            authState = stagingState;
            stagingState = new AuthState();
        }
        return globalconfiguration;
    }

    private void initializeErrorPageInternal(final HttpServletRequest request) {
        if (stagingState.administrator == null) {
            final String remoteAddr = request.getRemoteAddr();
            stagingState.administrator = new PublicAccessAuthenticationToken(remoteAddr, true);
        }
        commonInit();
        // Set ServletContext for reading language files from resources
        servletContext = request.getSession(true).getServletContext();
        if (currentAdminPreference == null) {
            currentAdminPreference = getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(), currentAdminPreference.getSecondaryLanguage());
        stagingState.errorpage_initialized = true;
    }

    /** Returns the current users common name */
    @Override
    public String getUsersCommonName() {
        return authState.usercommonname;
    }

    /** Returns the users certificate serialnumber, user to id the adminpreference. */
    @Override
    public String getCertificateFingerprint() {
        return authState.certificateFingerprint;
    }

    /** Return the admins selected theme including its trailing '.css' */
    @Override
    public String getCssFile() {
        return globalconfiguration == null ? null : globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentAdminPreference.getTheme() + ".css";
    }

    /** Return the IE fixes CSS of the admins selected theme including it's trailing '.css' */
    @Override
    public String getIeFixesCssFile() {
        return globalconfiguration == null ? null : globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentAdminPreference.getTheme()
                + globalconfiguration.getIeCssFilenamePostfix() + ".css";
    }

    /** Returns a version string for JavaScript and CSS file cache control */
    @Override
    public String getVersion() {
        return StaticResourceVersioning.VERSION;
    }

    /** Returns the admins prefered language */
    @Override
    public int getPreferedLanguage() {
        return currentAdminPreference.getPreferedLanguage();
    }

    /** Returns the admins secondary language. */
    @Override
    public int getSecondaryLanguage() {
        return currentAdminPreference.getSecondaryLanguage();
    }

    @Override
    public int getEntriesPerPage() {
        return currentAdminPreference.getEntriesPerPage();
    }

    @Override
    public int getLogEntriesPerPage() {
        return currentAdminPreference.getLogEntriesPerPage();
    }

    @Override
    public void setLogEntriesPerPage(final int logentriesperpage) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLogEntriesPerPage(logentriesperpage);
        saveCurrentAdminPreference();
    }

    @Override
    public int getLastFilterMode() {
        return currentAdminPreference.getLastFilterMode();
    }

    @Override
    public void setLastFilterMode(final int lastfiltermode) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLastFilterMode(lastfiltermode);
        saveCurrentAdminPreference();
    }

    @Override
    public int getLastEndEntityProfile() {
        return currentAdminPreference.getLastProfile();
    }

    @Override
    public void setLastEndEntityProfile(final int lastprofile) throws AdminDoesntExistException, AdminExistsException {
        currentAdminPreference.setLastProfile(lastprofile);
        saveCurrentAdminPreference();
    }

    @Override
    public boolean existsAdminPreference() {
        return adminPreferenceSession.existsAdminPreference(authState.administrator);
    }

    @Override
    public void addAdminPreference(final AdminPreference adminPreference) throws AdminExistsException {
        currentAdminPreference = adminPreference;
        if (!(authState.administrator instanceof PublicAccessAuthenticationToken)) {
            if (!adminPreferenceSession.addAdminPreference(authState.administrator, adminPreference)) {
                throw new AdminExistsException("Admin already exists in the database.");
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
        adminsweblanguage = new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    @Override
    public void changeAdminPreference(final AdminPreference adminPreference) throws AdminDoesntExistException {
        currentAdminPreference = adminPreference;
        if (!(authState.administrator instanceof PublicAccessAuthenticationToken)) {
            if (!adminPreferenceSession.changeAdminPreference(authState.administrator, adminPreference)) {
                throw new AdminDoesntExistException("Admin does not exist in the database.");
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
        adminsweblanguage = new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    /** @return the current admin's preference */
    @Override
    public AdminPreference getAdminPreference() {
        if (currentAdminPreference==null) {
            currentAdminPreference = adminPreferenceSession.getAdminPreference(authState.administrator);
            if (currentAdminPreference == null) {
                currentAdminPreference = getDefaultAdminPreference();
            }
        }
        return currentAdminPreference;
    }

    private void saveCurrentAdminPreference() throws AdminDoesntExistException, AdminExistsException {
        if (!(authState.administrator instanceof PublicAccessAuthenticationToken)) {
            if (existsAdminPreference()) {
                if (!adminPreferenceSession.changeAdminPreferenceNoLog(authState.administrator, currentAdminPreference)) {
                    throw new AdminDoesntExistException("Admin does not exist in the database.");
                }
            } else {
                if (!adminPreferenceSession.addAdminPreference(authState.administrator, currentAdminPreference)) {
                    throw new AdminExistsException("Admin already exists in the database.");
                }
            }
        } else {
            log.debug("Changes to admin preference will not be persisted for the currently logged in AuthenticationToken type and lost when the session ends.");
        }
    }

    @Override
    public AdminPreference getDefaultAdminPreference() {
        return adminPreferenceSession.getDefaultAdminPreference();
    }

    @Override
    public WebLanguagesImpl getWebLanguages() {
        return new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
                currentAdminPreference.getSecondaryLanguage());
    }

    @Override
    public void saveDefaultAdminPreference(final AdminPreference adminPreference) throws AuthorizationDeniedException {
        adminPreferenceSession.saveDefaultAdminPreference(authState.administrator, adminPreference);
        // Reload preferences
        currentAdminPreference = adminPreferenceSession.getAdminPreference(authState.administrator);
        if (currentAdminPreference == null) {
            currentAdminPreference = getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguagesImpl(servletContext, globalconfiguration, currentAdminPreference.getPreferedLanguage(),
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
    @Override
    @Deprecated
    public boolean isAuthorizedNoLog(final String... resources) throws AuthorizationDeniedException { // still used by JSP/JSF code (viewcertificate.xhtml)
        if (!authorizationSession.isAuthorizedNoLogging(authState.administrator, resources)) {
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
    @Override
    public boolean isAuthorizedNoLogSilent(final String... resources) {
        return authorizationSession.isAuthorizedNoLogging(authState.administrator, resources);
    }

    @Override
    public String getBaseUrl() {
        return globalconfiguration == null ? null : globalconfiguration.getRelativeUri();
    }

    @Override
    public String getAdminWebBaseUrl() {
        return globalconfiguration == null ? null : globalconfiguration.getRelativeUri() + globalconfiguration.getAdminWebPath();
    }

    @Override
    public String getReportsPath() {
        return globalconfiguration == null ? null : globalconfiguration.getReportsPath();
    }

    /* Returns the global configuration */
    @Override
    public GlobalConfiguration getGlobalConfiguration() {
        return globalconfiguration;
    }

    @Override
    public String getCurrentRemoteIp() {
        return authState.currentRemoteIp;
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

    @Override
    public String getImagePath(final String imagefilename) {
        if (globalconfiguration == null) {
            return null;
        }
        final String[] strs = adminsweblanguage.getAvailableLanguages();
        final int index = currentAdminPreference.getPreferedLanguage();
        final String prefered = strs[index];
        final String secondary = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getSecondaryLanguage()];

        final String imagefile = imagefilename.substring(0, imagefilename.lastIndexOf('.'));
        final String theme = currentAdminPreference.getTheme().toLowerCase();
        final String postfix = imagefilename.substring(imagefilename.lastIndexOf('.') + 1);

        final String[] filepaths = new String[] {
                "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + prefered + "." + postfix,
                "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + secondary + "." + postfix,
                "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + theme + "." + postfix,
                "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + prefered + "." + postfix,
                "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + secondary + "." + postfix,
        };
        for (final String filepath : filepaths) {
            if (this.getClass().getResourceAsStream(filepath) != null) {
                return filepath;
            }
        }
        return "/" + globalconfiguration.getImagesPath() + "/" + imagefile + "." + postfix;
    }

    @Deprecated
    @Override
    public String getImagefileInfix(final String imagefilename) {
        return getAdminWebBaseUrl() + getImagePath(imagefilename);
    }

    @Override
    public String getEditionFolder() {
        return isRunningEnterprise() ? "EE" : "CE";
    }

    @Override
    public String[] getAvailableLanguages() {
        return adminsweblanguage.getAvailableLanguages();
    }

    /** Returns a fallback text to be used if the session was not initialized properly */
    private String fallbackText(final String template, final Object... params) {
        final String msg = "Language was not initialized for this session";
        if (log.isTraceEnabled()) {
            log.trace(msg, new Exception("Stack trace")); // Included for stack trace
        } else {
            log.warn(msg);
        }
        if (params.length == 0) {
            return template;
        } else {
            return template + " (" + StringUtils.join(params, ", ") + ")";
        }
    }

    @Override
    public String getText(final String template) {
        if (adminsweblanguage == null) {
            return fallbackText(template);
        }
        return adminsweblanguage.getText(template);
    }

    @Override
    public List<WebLanguage> getWebLanguagesList() {
        return adminsweblanguage.getWebLanguages();
    }

    /**
     * @param template the entry in the language file to get
     * @param unescape true if html entities should be unescaped (&auml; converted to the real char)
     * @param params values of {0}, {1}, {2}... parameters
     * @return text string, possibly unescaped, or "template" if the template does not match any entry in the language files
     */
    @Override
    public String getText(final String template, final boolean unescape, final Object... params) {
        if (adminsweblanguage == null) {
            return fallbackText(template, params);
        }
        String str = adminsweblanguage.getText(template, params);
        if (unescape) {
            str = HTMLTools.htmlunescape(str);
            // log.debug("String after unescape: "+str);
            // If unescape == true it most likely means we will be displaying a javascript
            str = HTMLTools.javascriptEscape(str);
            // log.debug("String after javascriptEscape: "+str);
        }
        return str;
    }

    /** @return a more user friendly representation of a Date. */
    @Override
    public String formatAsISO8601(final Date date) {
        return ValidityDate.formatAsISO8601(date, timeZone);
    }

    /** Check if the argument is a relative date/time in the form days:min:seconds. */
    @Override
    public boolean isRelativeDateTime(final String dateString) {
        return dateString.matches("^\\d+:\\d?\\d:\\d?\\d$");
    }

    /** To be used when giving format example. */
    @Override
    public String getDateExample() {
        return "[" + ValidityDate.ISO8601_DATE_FORMAT + "]: '" + formatAsISO8601(new Date()) + "'";
    }

    /** Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. */
    @Override
    public String getImpliedUTCFromISO8601(final String dateString) throws ParseException {
        return ValidityDate.getImpliedUTCFromISO8601(dateString);
    }

    /**
     * Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. If it is a relative date we
     * return it as it was. Otherwise we try to parse it as a ISO8601 date time.
     */
    @Override
    public String getImpliedUTCFromISO8601OrRelative(final String dateString) throws ParseException {
        if (StringUtils.isEmpty(dateString)) {
            return "";
        }
        if (!isRelativeDateTime(dateString)) {
            return getImpliedUTCFromISO8601(dateString);
        }
        return dateString;
    }

    /** Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". */
    @Override
    public String getISO8601FromImpliedUTC(final String dateString) throws ParseException {
        return ValidityDate.getISO8601FromImpliedUTC(dateString, timeZone);
    }

    /**
     * Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". If it is a relative date we
     * return it as it was. If we fail to parse the stored date we return an error-string followed by the stored value.
     * If the passed in value is empty, we return an empty string
     */
    @Override
    public String getISO8601FromImpliedUTCOrRelative(final String dateString) {
        if (StringUtils.isEmpty(dateString)) {
            return "";
        }
        if (!isRelativeDateTime(dateString)) {
            try {
                return getISO8601FromImpliedUTC(dateString);
            } catch (final ParseException e) {
                log.debug(e.getMessage());
                // If we somehow managed to store an invalid date, we want to give the admin the option
                // to correct this. If we just throw an Exception here it would not be possible.
                return "INVALID: " + dateString;
            }
        }
        return dateString;
    }

    @Override
    public void reloadGlobalConfiguration() {
        globalconfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalconfiguration.initializeAdminWeb();
    }

    @Override
    public void saveGlobalConfiguration(final GlobalConfiguration gc) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authState.administrator, gc);
        reloadGlobalConfiguration();
    }

    @Override
    public void saveGlobalConfiguration() throws Exception {
        globalConfigurationSession.saveConfiguration(authState.administrator, globalconfiguration);
    }

    /**
     * Save the given CMP configuration.
     *
     * @param cmpconfiguration A CMPConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    @Override
    public void saveCmpConfiguration(final CmpConfiguration cmpconfiguration) throws AuthorizationDeniedException {
        this.cmpconfiguration = cmpconfiguration;
        globalConfigurationSession.saveConfiguration(authState.administrator, cmpconfiguration);
    }

    /**
     * Save the given MSAutoEnrollmentConfiguration configuration.
     *
     * @param msAutoEnrollmentConfiguration A MSAutoEnrollmentConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    @Override
    public void saveMSAutoenrollmentConfiguration(final MSAutoEnrollmentConfiguration msAutoEnrollmentConfiguration) throws AuthorizationDeniedException {
        this.msAutoenrollmentConfig = msAutoEnrollmentConfiguration;
        globalConfigurationSession.saveConfiguration(authState.administrator, msAutoEnrollmentConfiguration);
    }
    
    /**
     * Save the given EST configuration.
     *
     * @param estconfiguration A EstConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    @Override
    public void saveEstConfiguration(final EstConfiguration estconfiguration) throws AuthorizationDeniedException {
        this.estconfiguration = estconfiguration;
        globalConfigurationSession.saveConfiguration(authState.administrator, estconfiguration);
    }

    /**
     * Reload the current configuration from the database.
     */
    @Override
    public void reloadCmpConfiguration() {
        cmpconfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    @Override
    public void reloadAutoenrollmentConfiguration() {
        msAutoenrollmentConfig =  (MSAutoEnrollmentConfiguration) globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);
    }
    
    @Override
    public void reloadEstConfiguration() {
        estconfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
    }

    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getCAIdToNameMap instead. */
    @Override
    @Deprecated
    public Map<Integer,String> getCAIdToNameMap() {
        return caSession.getCAIdToNameMap();
    }

    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaIds instead. */
    @Override
    @Deprecated
    public List<Integer> getAuthorizedCAIds() {
        return caSession.getAuthorizedCaIds(authState.administrator);
    }

    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaNamesToIds instead. */
    @Override
    @Deprecated
    public TreeMap<String,Integer> getCANames() {
        return caSession.getAuthorizedCaNamesToIds(authState.administrator);
    }

    @Override
    public TreeMap<String,Integer> getExternalCANames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        for (final CAInfo caInfo : caSession.getAuthorizedCaInfos(authState.administrator)) {
            if (caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                ret.put(caInfo.getName(), caInfo.getCAId());
            }
        }
        return ret;
    }

    @Override
    public TreeMap<String,Integer> getActiveCANames() {
        final TreeMap<String, Integer> ret = new TreeMap<>();
        final Map<Integer, String> idtonamemap = this.caSession.getActiveCAIdToNameMap(authState.administrator);
        for (final Integer id : idtonamemap.keySet()) {
            ret.put(idtonamemap.get(id), id);
        }
        return ret;
    }

    /**
     * Returns names of authorized Certificate Profile of 'End Entity' type.
     * @return TreeMap of name (String) -> id (Integer)
     */
    @Override
    public TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_ENDENTITY);

        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    @Override
    public TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_SUBCA);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }
    
    @Override
    public TreeMap<String, Integer>  getAuthorizedSshCertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_SSH);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    @Override
    public TreeMap<String, Integer>  getAuthorizedItsCertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_ITS);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }

    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    @Override
    public TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_ROOTCA);
        final Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (final int id : authorizedIds) {
            ret.put(idtonamemap.get(id),id);
        }
        return ret;
    }
    
    /**
     * Returns authorized ITS CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    @Override
    public TreeMap<String, Integer> getAuthorizedItsCACertificateProfileNames() {
        final TreeMap<String,Integer> ret = new TreeMap<>();
        final List<Integer> authorizedIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, CertificateConstants.CERTTYPE_ITS);
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
    @Override
    public Map<Integer, String> getApprovalProfileIdToNameMap() {
        final Map<Integer, String> approvalProfileMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        approvalProfileMap.put(-1, getText("NONE"));
        return approvalProfileMap;
    }

    @Override
    public List<Integer> getSortedApprovalProfileIds() {
        final List<ApprovalProfile> sortedProfiles = new ArrayList<>(approvalProfileSession.getAllApprovalProfiles().values());
        Collections.sort(sortedProfiles);
        final List<Integer> result = new ArrayList<>();
        result.add(-1);
        for(final ApprovalProfile approvalProfile : sortedProfiles) {
            result.add(approvalProfile.getProfileId());
        }
        return result;
    }

    /**
     * @return all authorized publishers names as a list
     */
    @Override
    public List<String> getAuthorizedPublisherNames() {
        return new ArrayList<>(getAuthorizedPublisherNamesAndIds().keySet());
    }

    /**
     * @return all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    @Override
    public TreeMap<String,Integer> getAuthorizedPublisherNamesAndIds() {
        final TreeMap<String,Integer> result = new TreeMap<>();
        final Map<Integer, String> idToNameMap = publisherSession.getPublisherIdToNameMap();
        for(final int id : caAdminSession.getAuthorizedPublisherIds(authState.administrator)) {
            if (idToNameMap.get(id) == null) {
                log.warn("Publisher with ID " + id + " exists but can not be accessed. There may be a duplicate name. Please rename or delete.");
                continue; // prevent NPE below
            }
            result.put(idToNameMap.get(id), id);
        }
        return result;
    }

    /**
     * Method returning the all available publishers id to name.
     *
     * @return the publisheridtonamemap (HashMap) sorted by value
     */
    @Override
    public Map<Integer, String> getPublisherIdToNameMapByValue() {
        final Map<Integer,String> publisheridtonamemap = publisherSession.getPublisherIdToNameMap();
        final List<Map.Entry<Integer, String>> publisherIdToNameMapList = new LinkedList<>(publisheridtonamemap.entrySet());
        publisherIdToNameMapList.sort((o1, o2) -> {
            if (o1 == null) {
                return o2 == null ? 0 : -1;
            } else if (o2 == null) {
                return 1;
            }
            return o1.getValue().compareToIgnoreCase(o2.getValue());
        });
        final Map<Integer, String> sortedMap = new LinkedHashMap<>();
        for (final Map.Entry<Integer, String> entry : publisherIdToNameMapList) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }
        return sortedMap;
    }

    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (String)
     */
    @Override
    public TreeMap<String, String> getAuthorizedEndEntityProfileNames(final String endentityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(authState.administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        return raAuthorization.getAuthorizedEndEntityProfileNames(endentityAccessRule);
    }

    @Override
    public AuthenticationToken getAdminObject() {
        return authState.administrator;
    }

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     *
     * @return true if key strength is limited
     */
    @Override
    public boolean isUsingExportableCryptography() {
        return KeyTools.isUsingExportableCryptography();
    }

    @Override
    public boolean isPostUpgradeRequired() {
        return upgradeSession.isPostUpgradeNeeded();
    }

    /**
     * @return The host's name or "unknown" if it could not be determined.
     */
    @Override
    public String getHostName() {
        String hostname = "unknown";
        try {
            final InetAddress addr = InetAddress.getLocalHost();
            // Get hostname
            hostname = addr.getHostName();
        } catch (final UnknownHostException e) {
            // Ignored
        }
        return hostname;
    }

    /** @return The current time on the server */
    @Override
    public String getServerTime() {
        return ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_SERVER);
    }

    /**
     * Uses the language in the Administration GUI to determine which locale is preferred.
     *
     * @return the locale of the Admin GUI
     */
    @Override
    public Locale getLocale() {
        final Locale[] locales = DateFormat.getAvailableLocales(); // TODO: Why not use Locale.getAvailableLocales()? Difference?
        Locale returnValue = null;
        final String prefered = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getPreferedLanguage()];
        final String secondary = adminsweblanguage.getAvailableLanguages()[currentAdminPreference.getSecondaryLanguage()];
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

    @Override
    public boolean isSessionTimeoutEnabled() {
        return globalconfiguration == null ? GlobalConfiguration.DEFAULTSESSIONTIMEOUT : globalconfiguration.getUseSessionTimeout();
    }

    @Override
    public int getSessionTimeoutTime() {
        return globalconfiguration == null ? GlobalConfiguration.DEFAULTSESSIONTIMEOUTTIME : globalconfiguration.getSessionTimeoutTime();
    }

    @Override
    public boolean isHelpEnabled() {
        return !"disabled".equalsIgnoreCase(WebConfiguration.getDocBaseUri());
    }

    @Override
    public String getHelpBaseURI() {
        final String helpBaseURI = WebConfiguration.getDocBaseUri();
        if ("internal".equalsIgnoreCase(helpBaseURI)) {
            return getBaseUrl() + "doc";
        } else {
            return helpBaseURI;
        }
    }

    @Override
    public String getHelpReference(final String lastPart) {
        if (!isHelpEnabled()) {
            return "";
        }
        return "[<a href=\"" + getHelpBaseURI() + lastPart + "\" target=\"" + GlobalConfiguration.DOCWINDOW + "\" rel=\"noopener noreferer\" title=\""
                + getText("OPENHELPSECTION") + "\" >?</a>]";
    }

    @Override
    public String getExternalHelpReference(final String linkPart) {
        if (!isHelpEnabled()) {
            return "";
        }
        return "[<a href=\"" + linkPart + "\" target=\"" + GlobalConfiguration.DOCWINDOW + "\" rel=\"noopener noreferer\" title=\"" + getText("OPENHELPSECTION") + "\" >?</a>]";
    }

    @Override
    public String[] getCertSernoAndIssuerdn(final String certdata) {
        final String[] ret = StringTools.parseCertData(certdata);
        if (log.isDebugEnabled()) {
            log.debug("getCertSernoAndIssuerdn: " + certdata + " -> " + (ret==null?"null":(ret[0] + "," + ret[1])));
        }
        return ret;
    }

    @Override
    public String getCleanOption(final String parameter, final String[] validOptions) {
        for (int i = 0; i < validOptions.length; i++) {
            if (parameter.equals(validOptions[i])) {
                return parameter;
            }
        }
        throw new IllegalArgumentException("Parameter " + parameter + " not found among valid options.");
    }

    @Override
    public void clearClusterCache(final boolean excludeActiveCryptoTokens) throws CacheClearException {
        if (log.isTraceEnabled()) {
            log.trace(">clearClusterCache");
        }
        // Clear local caches by direct EJB invocation
        clearCacheSession.clearCaches(excludeActiveCryptoTokens);
        String localhostName = "localhost";
        final StringBuilder failedHosts = new StringBuilder();
        final StringBuilder succeededHost = new StringBuilder();
        for (final String host : globalconfiguration.getNodesInCluster()) {
            if (host != null) {
                if (isLocalHost(host)) {
                    // Show hostname as in previous EJBCA versions if node tracking is enabled
                    localhostName = host;
                } else {
                    if (checkHost(host, excludeActiveCryptoTokens)) {
                        succeededHost.append(SINGLE_SPACE_CHAR).append(host);
                    } else {
                        failedHosts.append(SINGLE_SPACE_CHAR).append(host);
                    }
                }
            }
        }
        succeededHost.append(SINGLE_SPACE_CHAR).append(localhostName);
        // Invalidate local GUI cache
        authState.initialized = false;
        if (failedHosts.length() > 0) {
            // The below will print hosts starting with a blank (space), but it's worth it to not have to consider error handling if toString is empty
            throw new CacheClearException("Failed to clear cache on hosts (" + failedHosts + "), but succeeded on (" + succeededHost + ").");
        }
        if (log.isTraceEnabled()) {
            log.trace("<clearClusterCache");
        }
    }

    /** Perform HTTP connection to the cluster nodes clear-cache Servlet
     * @param hostname hostname of the server to clear cache on
     * @param excludeActiveCryptoTokens indicating if clearing cache should clear crypt token cache of active crypto tokens, which typically disabled non auto activated tokens
     * @return true if the connection was successful and cache cleared, false if cache could not be cleared.
     */
    private boolean checkHost(final String hostname, final boolean excludeActiveCryptoTokens) {
        // get http port of remote host, this requires that all cluster nodes uses the same public http port
        final int pubport = WebConfiguration.getPublicHttpPort();
        final String requestUrl = "http://" + hostname + ":" + pubport + "/ejbca/clearcache?command=clearcaches&excludeactivects="
                + excludeActiveCryptoTokens;
        if (log.isDebugEnabled()) {
            log.debug("Contacting host with url:" + requestUrl);
        }
        if (StringUtils.isNotEmpty(hostname)) {
            try {
                final URL url = new URL(requestUrl);
                final HttpURLConnection con = (HttpURLConnection) url.openConnection();
                final int responseCode = con.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    return true;
                } else if(responseCode == HttpURLConnection.HTTP_MOVED_TEMP || 
                        responseCode == HttpURLConnection.HTTP_MOVED_PERM) { 
                    // only happens if redirect is https
                    // https redirects may be setup by wildfly filters or (reverse-)proxies
                    return followHttpsRedirect(con.getHeaderField("Location"), 0, hostname);
                }
                log.info("Failed to clear caches for host: " + hostname + ", responseCode=" + responseCode);
            } catch (final IOException e) {
                log.info("Failed to clear caches for host: " + hostname + ", message=" + e.getMessage());
            }
        } else {
            log.info("Not clearing cache for host with empty hostname.");
        }
        return false;
    }
    
    private boolean followHttpsRedirect(String redirectUri, int redirectAttempt, String hostname) {
        
        if(StringUtils.isBlank(redirectUri)) {
            return false;
        }
        SSLContext context = null;
        try {
            context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { new X509TrustManagerAcceptAll() }, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
        
        HttpsURLConnection conn = null;
        try {
            URL url = new URL(redirectUri);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setSSLSocketFactory(context.getSocketFactory());
            conn.setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String arg0, SSLSession arg1) {
                    return true;
                }
            });
            conn.connect();
            
            int responseCode = conn.getResponseCode();
            log.info("Cache clearance redirect attempt: " + redirectAttempt  + " at: " + redirectUri + 
                                    " response: " + responseCode);
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return true;
            } else if((responseCode == HttpURLConnection.HTTP_MOVED_TEMP || 
                responseCode == HttpURLConnection.HTTP_MOVED_PERM) && redirectAttempt < 3) {
                return followHttpsRedirect(conn.getHeaderField("Location"), redirectAttempt+1, hostname);
            }
        } catch (IOException e) {
            log.error("Cache clearance redirect attempt failed with exception: " + e.getMessage());
        }
        
        log.info("Failed to clear caches for host: " + hostname);
        return false;
        
    }

    /** @return true if the provided hostname matches the name reported by the system for localhost */
    private boolean isLocalHost(final String hostname) {
        try {
            if (hostname.equals(InetAddress.getLocalHost().getHostName())) {
                return true;
            }
        } catch (final UnknownHostException e) {
            log.error("Hostname could not be determined", e);
        }
        return false;
    }

    @Override
    public EjbBridgeSessionLocal getEjb() {
        return ejbLocalHelper;
    }

    @Override
    public EnterpriseEditionEjbBridgeSessionLocal getEnterpriseEjb() {
        return enterpriseEjbLocalHelper;
    }

    //**********************
    //     CMP
    //**********************

    @Override
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
    @Override
    public CmpConfiguration getCmpConfigForEdit(final String alias) {
        if (cmpConfigForEdit != null) {
            return cmpConfigForEdit;
        }
        reloadCmpConfiguration();
        cmpConfigForEdit = new CmpConfiguration();
        cmpConfigForEdit.setAliasList(new LinkedHashSet<>());
        cmpConfigForEdit.addAlias(alias);
        for(final String key : CmpConfiguration.getAllAliasKeys(alias)) {
            final String value = cmpconfiguration.getValue(key, alias);
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
    @Override
    public void updateCmpConfigFromClone(final String alias) throws AuthorizationDeniedException {
        if (cmpconfiguration.aliasExists(alias) && cmpConfigForEdit.aliasExists(alias)) {
            for(final String key : CmpConfiguration.getAllAliasKeys(alias)) {
                final String value = cmpConfigForEdit.getValue(key, alias);
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
    @Override
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
    @Override
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
    @Override
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
    @Override
    public void renameCmpAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        cmpconfiguration.renameAlias(oldName, newName);
        saveCmpConfiguration(cmpconfiguration);
    }

    @Override
    public void clearCmpConfigClone() {
        cmpConfigForEdit = null;
    }

    @Override
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
        final CmpConfiguration returnValue = new CmpConfiguration(cmpConfiguration);
        //Build a lookup map due to the fact that default CA is stored as a SubjectDNs
        final Map<String, String> subjectDnToCaNameMap = new HashMap<>();
        for (final int caId : caSession.getAllCaIds()) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caId);
            if (caInfo != null) {
                subjectDnToCaNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
            }
        }
        final Set<Integer> authorizedProfileIds = new HashSet<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authState.administrator, ""));
        //Exclude all aliases which refer to CAs that current admin doesn't have access to
        aliasloop: for (final String alias : new ArrayList<>(cmpConfiguration.getAliasList())) {
            //Collect CA names
            final Set<String> caNames = new HashSet<>();
            final String defaultCaSubjectDn = cmpConfiguration.getCMPDefaultCA(alias);
            if (!StringUtils.isEmpty(defaultCaSubjectDn)) {
                caNames.add(subjectDnToCaNameMap.get(defaultCaSubjectDn));
            }
            if (cmpConfiguration.getRAMode(alias)) {
                final String authenticationCa = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, alias);
                if (!StringUtils.isEmpty(authenticationCa)) {
                    caNames.add(authenticationCa);
                }
                final String raCaName = cmpconfiguration.getRACAName(alias);
                if (!"ProfileDefault".equals(raCaName)) {
                    // "ProfileDefault" is not a CA name and if the profile default is used, this will be implicitly checked be checking access to the EEP
                    caNames.add(raCaName);
                }
                final String eeProfileIdString = cmpconfiguration.getRAEEProfile(alias);
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
            final TreeMap<String, Integer> caNameToIdMap = caSession.getAuthorizedCaNamesToIds(authState.administrator);
            for (final String caName : caNames) {
                if(caName != null) { //CA might have been removed
                    final Integer caId = caNameToIdMap.get(caName);
                    if (caId != null) {
                        if (!caSession.authorizedToCANoLogging(authState.administrator, caId)) {
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
    @Override
    public Map<String, String> getAuthorizedEEProfileNamesAndIds(final String endEntityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(authState.administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        final TreeMap<String, String> authorizedEEProfileNamesAndIds = new TreeMap<>(
                raAuthorization.getAuthorizedEndEntityProfileNames(endEntityAccessRule));
        // Add KeyId option. If used, extract the EE profile name from the senderKID field of the CMP request.
        // Important to add KeyId entry to a fresh copy, since the "Add End Entity" page will try to load end
        // entity profiles from this map.
        authorizedEEProfileNamesAndIds.put(CmpConfiguration.PROFILE_USE_KEYID, CmpConfiguration.PROFILE_USE_KEYID);
        return authorizedEEProfileNamesAndIds;
    }

    @Override
    public Map<String, String> getAuthorizedEEProfilesAndIdsNoKeyId(final String endEntityAccessRule) {
        final RAAuthorization raAuthorization = new RAAuthorization(authState.administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        return new TreeMap<>(raAuthorization.getAuthorizedEndEntityProfileNames(endEntityAccessRule));
    }

    /**
     * Retrieve a collection of available certificate authority ids based on end entity profile id. The returned list may
     * contain an additional "KeyID" option which allows the end user to specify the CA in the CMP request.
     * @param endEntityProfileId the id of an end entity profile
     * @return a sorted list of certificate authorities for the specified end entity profile
     * @throws NumberFormatException if the end entity profile id is not a number
     * @throws AuthorizationDeniedException if we were denied access control
     */
    @Override
    public Collection<String> getAvailableCAsOfEEProfile(final String endEntityProfileId)
            throws NumberFormatException, AuthorizationDeniedException {
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
            final CACommon ca = caSession.getCANoLog(authState.administrator, id, null);
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
    @Override
    public Collection<String> getAvailableCertProfilesOfEEProfile(final String endEntityProfileId) {
        if (StringUtils.equals(endEntityProfileId, CmpConfiguration.PROFILE_USE_KEYID)) {
            final List<Integer> allCertificateProfileIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authState.administrator, 0);
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

    private Collection<Integer> getAvailableCertProfileIDsOfEEProfile(final String endEntityProfileId) {
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(Integer.valueOf(endEntityProfileId));
        if (profile == null) {
            return Collections.emptyList();
        }
        return profile.getAvailableCertificateProfileIds();
    }

    /**
     * Retrieve a mapping between certificate profiles names and IDs available in the end entity profile. To be displayed in the GUI.
     * @param endEntityProfileId the the end entity profile in which we want to find certificate profiles
     * @return a map (TreeMap so it's sorted by key) {certificate profile name, certificate profile id} with authorized certificate profiles
     */
    @Override
    public Map<String, Integer> getCertificateProfilesNoKeyId(final String endEntityProfileId) {
        final Map<Integer, String> map = certificateProfileSession.getCertificateProfileIdToNameMap();
        final TreeMap<String, Integer> certificateProfiles = new TreeMap<>();
        final Collection<Integer> ids = getAvailableCertProfileIDsOfEEProfile(endEntityProfileId);
        for (final int id : ids) {
            final String name = map.get(id);
            if (name == null) {
                log.warn("Missing Certificate Profile " + id + " referenced from End Entity Profile with ID " + endEntityProfileId);
                continue;
            }
            certificateProfiles.put(name, id);
        }
        return certificateProfiles;
    }

    @Override
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

    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaNamesToIds instead. */
    @Override
    @Deprecated
    public TreeMap<String, Integer> getCAOptions() {
        return getCANames();
    }

    /**
     * Gets the list of CA names by the list of CA IDs.
     * @param idString the semicolon separated list of CA IDs.
     * @return the list of CA names as semicolon separated String.
     * @throws NumberFormatException if a CA ID could not be parsed.
     */
    @Override
    public String getCaNamesString(final String idString) throws NumberFormatException {
        final TreeMap<String, Integer> availableCas = getCAOptions();
        final List<String> result = new ArrayList<>();
        if (StringUtils.isNotBlank(idString)) {
            for (final String id : idString.split(SEMICOLON)) {
                if (availableCas.containsValue(Integer.valueOf(id))) {
                    for (final Entry<String,Integer> entry : availableCas.entrySet()) {
                        if (entry.getValue() != null && entry.getValue().equals( Integer.valueOf(id))) {
                            result.add(entry.getKey());
                        }
                    }
                }
            }
        }
        return StringUtils.join(result, SEMICOLON);
    }

    /** @return true if we are running in the enterprise mode otherwise false. */
    @Override
    public boolean isRunningEnterprise() {
        return enterpriseEjbLocalHelper.isRunningEnterprise();
    }

    /** @return true if we are running an EJBCA build that has CA functionality enabled. */
    @Override
    public boolean isRunningBuildWithCA() {
        return isRunningBuildWith("org.cesecore.certificates.ca.X509CAImpl");
    }

    /** @return true if we are running an EJBCA build that has RA functionality enabled.
     * The check is implemented to look for RaMasterApiPeerImpl, as it is excluded from the "variant=va ziprelease.
     * We decided to use RaMasterApiPeerImpl for this check, because it seemd the most painless one among
     * the excluded classes to perform this check against: it is visible here in EjbcaWebBeanImpl and it doesn't have
     * many dependencies to disturb the exclusion.
     * */
    @Override
    public boolean isRunningBuildWithRA() {
        return isRunningBuildWith("org.ejbca.peerconnector.ra.RaMasterApiPeerImpl");
    }

    /** @return true if we are running EJBCA build that has VA functionality enabled. */
    @Override
    public boolean isRunningBuildWithVA() {
        return isRunningBuildWithCA() || !isRunningBuildWithRA();
    }

    private static boolean isRunningBuildWith(String className) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @Override
    public boolean isRunningBuildWithRAWeb() {
        return !isRunningEnterprise() || isRunningBuildWithRA();
    }

    @Override
    public MSAutoEnrollmentConfiguration getAutoenrollConfiguration() {
        if (msAutoenrollmentConfig == null) {
            reloadAutoenrollmentConfiguration();
        }
        return msAutoenrollmentConfig;
    }
    
    /**
     * Merges together an alias from the editing clone into the proper configuration cache and saves it to the database.
     *
     * @param alias a Autoenrollment config alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    @Override
    public void updateAutoenrollConfigFromClone(final String alias) throws AuthorizationDeniedException {
        if (msAutoenrollmentConfig.aliasExists(alias) && msAutoenrollmentConfigForEdit.aliasExists(alias)) {
            for(final String key : MSAutoEnrollmentConfiguration.getAllAliasKeys(alias)) {
                final String value = msAutoenrollmentConfigForEdit.getValue(key, alias);
                msAutoenrollmentConfig.setValue(key, value, alias);
            }
        }
        saveMSAutoenrollmentConfiguration(msAutoenrollmentConfig);
    }

    /**
     * Adds an alias to the database.
     *
     * @param alias the name of a Autoenrollment alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    @Override
    public void addAutoenrollAlias(final String alias) throws AuthorizationDeniedException {
        msAutoenrollmentConfig.addAlias(alias);
        saveMSAutoenrollmentConfiguration(msAutoenrollmentConfig);
    }

    /**
     * Makes a copy of a given alias
     *
     * @param oldName the name of the alias to copy
     * @param newName the name of the new alias
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    @Override
    public void cloneAutoenrollAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        msAutoenrollmentConfig.cloneAlias(oldName, newName);
        saveMSAutoenrollmentConfiguration(msAutoenrollmentConfig);
    }

    /**
     * Deletes a Autoenrollment alias from the database.
     *
     * @param alias the name of the alias to delete.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    @Override
    public void removeAutoenrollAlias(final String alias) throws AuthorizationDeniedException {
        msAutoenrollmentConfig.removeAlias(alias);
        saveMSAutoenrollmentConfiguration(msAutoenrollmentConfig);
    }

    /**
     * Renames a Autoenrollment alias
     *
     * @param oldName the old alias name
     * @param newName the new alias name
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    @Override
    public void renameAutoenrollAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        msAutoenrollmentConfig.renameAlias(oldName, newName);
        saveMSAutoenrollmentConfiguration(msAutoenrollmentConfig);
    }

    @Override
    public void clearAutoenrollConfigClone() {
        msAutoenrollmentConfig = null;
    }

    @Override
    public void clearAutoenrollCache() {
        globalConfigurationSession.flushConfigurationCache(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);
        reloadAutoenrollmentConfiguration();
    }
    
    @Override
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
    @Override
    public EstConfiguration getEstConfigForEdit(final String alias) {
        if (estConfigForEdit != null) {
            return estConfigForEdit;
        }
        reloadEstConfiguration();
        estConfigForEdit = new EstConfiguration();
        estConfigForEdit.setAliasList(new LinkedHashSet<>());
        estConfigForEdit.addAlias(alias);
        for(final String key : EstConfiguration.getAllAliasKeys(alias)) {
            final String value = estconfiguration.getValue(key, alias);
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
    @Override
    public void updateEstConfigFromClone(final String alias) throws AuthorizationDeniedException {
        if (estconfiguration.aliasExists(alias) && estConfigForEdit.aliasExists(alias)) {
            for(final String key : EstConfiguration.getAllAliasKeys(alias)) {
                final String value = estConfigForEdit.getValue(key, alias);
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
    @Override
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
    @Override
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
    @Override
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
    @Override
    public void renameEstAlias(final String oldName, final String newName) throws AuthorizationDeniedException {
        estconfiguration.renameAlias(oldName, newName);
        saveEstConfiguration(estconfiguration);
    }

    @Override
    public void clearEstConfigClone() {
        estConfigForEdit = null;
    }

    @Override
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
        final EstConfiguration returnValue = new EstConfiguration(estConfiguration);
        //Exclude all aliases which refer to CAs that current admin doesn't have access to
        aliasloop: for (final String alias : new ArrayList<>(estConfiguration.getAliasList())) {
            Integer caId = 0;
            // To be backward compatible with EJBCA 6.11, where this was stored as the name instead of ID, we make it possible to use both. See ECA-6556
            final String defaultCAIDStr = estConfiguration.getDefaultCAID(alias);
            if (NumberUtils.isNumber(defaultCAIDStr)) {
                caId = Integer.valueOf(defaultCAIDStr);
            } else if (StringUtils.isNotEmpty(defaultCAIDStr)) {
                // We have a caName, and want the Id
                final CAInfo cainfo = caSession.getCAInfoInternal(-1, defaultCAIDStr, true);
                if (cainfo != null) {
                    caId = cainfo.getCAId();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("CA with name '"+defaultCAIDStr+"' does not exist, allowing everyone to view EST alias '"+alias+"'.");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No default CA configured, allowing everyone to view EST alias '"+alias+"'.");
                }
            }
            if (caId != 0) {
                if (!caSession.authorizedToCANoLogging(authState.administrator, caId)) {
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

    @Override
    public AvailableExtendedKeyUsagesConfiguration getAvailableExtendedKeyUsagesConfiguration() {
        if (availableExtendedKeyUsagesConfig == null) {
            reloadAvailableExtendedKeyUsagesConfiguration();
        }
        return availableExtendedKeyUsagesConfig;
    }

    @Override
    public void reloadAvailableExtendedKeyUsagesConfiguration() {
        availableExtendedKeyUsagesConfig = (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
    }

    @Override
    public void saveAvailableExtendedKeyUsagesConfiguration(final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authState.administrator, ekuConfig);
        availableExtendedKeyUsagesConfig = ekuConfig;
    }

    //*************************************************
    //      OAuth trusted provider configurations
    //*************************************************
    @Override
    public OAuthConfiguration getOAuthConfiguration() {
        if (oAuthConfiguration == null) {
            reloadOAuthConfiguration();
        }
        return oAuthConfiguration;
    }

    @Override
    public void reloadOAuthConfiguration() {
        oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession
                .getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
    }

    @Override
    public void saveOAuthConfiguration(final OAuthConfiguration oAuthConfig) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authState.administrator, oAuthConfig);
        oAuthConfiguration = oAuthConfig;
    }
    //*************************************************
    //      External Account Binding  configurations
    //*************************************************

    @Override
    public EABConfiguration getEABConfiguration() {
        if (eabConfiguration == null) {
            reloadEABConfiguration();
        }
        return eabConfiguration;
    }

    @Override
    public void reloadEABConfiguration() {
        eabConfiguration = (EABConfiguration) globalConfigurationSession
                .getCachedConfiguration(EABConfiguration.EAB_CONFIGURATION_ID);
    }

    @Override
    public void saveEABConfiguration(EABConfiguration eabConfiguration) throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authState.administrator, eabConfiguration);
        this.eabConfiguration = eabConfiguration;
    }


    //*****************************************************************
    //       AvailableCustomCertificateExtensionsConfiguration
    //*****************************************************************

    @Override
    public AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsConfiguration() {
        if (availableCustomCertExtensionsConfig == null) {
            reloadAvailableCustomCertExtensionsConfiguration();
        }
        return availableCustomCertExtensionsConfig;
    }

    @Override
    public void reloadAvailableCustomCertExtensionsConfiguration() {
        availableCustomCertExtensionsConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
    }

    @Override
    public void saveAvailableCustomCertExtensionsConfiguration(final AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authState.administrator, cceConfig);
        availableCustomCertExtensionsConfig = cceConfig;
    }

    //*******************************
    //         Peer Connector
    //*******************************

    private Boolean peerConnectorPresent = null;

    /** @return true if the PeerConnectors GUI implementation is present. */
    @Override
    public boolean isPeerConnectorPresent() {
        if (peerConnectorPresent == null) {
            try {
                Class.forName("org.ejbca.ui.web.admin.peerconnector.PeerConnectorsMBean");
                peerConnectorPresent = Boolean.TRUE;
            } catch (final ClassNotFoundException e) {
                peerConnectorPresent = Boolean.FALSE;
            }
        }
        return peerConnectorPresent.booleanValue();
    }

    public boolean getRenderPublicAccessRemoval() {
        if (!isAuthorizedNoLogSilent(new String[]{String.valueOf(StandardRules.ROLE_ROOT)})) {
            return false;
        }

        List<RoleMember> members;
        try {
            Role superAdminRole = roleSession.getRole(authState.administrator, null, SUPERADMIN_ROLE);
            if (Objects.isNull(superAdminRole)) {
                return false;
            }
            List<Role> currentUserRoles = roleSession.getRolesAuthenticationTokenIsMemberOf(authState.administrator);
            boolean isSuperAdmin = currentUserRoles.stream().anyMatch(role -> role.equals(superAdminRole));
            if (!isSuperAdmin) {
                return false;
            }
            members = roleMemberSession.getRoleMembersByRoleId(authState.administrator,superAdminRole.getRoleId());
        } catch (AuthorizationDeniedException e) {
            return false;
        }
        boolean hasPublicAccessMember = false;
        if(members.size() > 0) {
            hasPublicAccessMember = members.stream().anyMatch(member -> member.getTokenType().equals(PUBLIC_ACCESS_AUTHENTICATION_TOKEN));
        }
        return hasPublicAccessMember;
    }

    public void removePublicAccessRoleMember() throws AuthorizationDeniedException {
        Role superAdminRole = roleSession.getRole(authState.administrator, null, SUPERADMIN_ROLE);
        List<RoleMember> members = roleMemberSession.getRoleMembersByRoleId(authState.administrator,superAdminRole.getRoleId());

        List<Integer> publicAccessMembers = members.stream()
            .filter(member -> member.getTokenType().equals(PUBLIC_ACCESS_AUTHENTICATION_TOKEN))
            .map(member -> member.getId())
            .collect(Collectors.toList());

        for (int member: publicAccessMembers) {
            roleMemberSession.remove(authState.administrator, member);
        }
    }

}
