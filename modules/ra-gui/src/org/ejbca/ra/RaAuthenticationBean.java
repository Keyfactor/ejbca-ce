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
package org.ejbca.ra;

import java.io.IOException;
import java.io.Serializable;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.faces.context.FacesContext;
import javax.inject.Named;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionEvent;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.CertTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * JSF Managed Bean for handling authentication of clients.
 *
 */
@Named
@SessionScoped
public class RaAuthenticationBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaAuthenticationBean.class);

    // JavaServlet Specification 2.5 Section 7.1.1: "...The name of the session tracking cookie must be JSESSIONID".
    private static final String SESSIONCOOKIENAME = "JSESSIONID";
    
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    private RaAuthenticationHelper raAuthenticationHelper = null;
    private AuthenticationToken authenticationToken = null;
    private X509Certificate x509Certificate = null;

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    public AuthenticationToken getAuthenticationToken() {
        if (raAuthenticationHelper==null) {
            raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession, raMasterApi);
        }
        authenticationToken = raAuthenticationHelper.getAuthenticationToken(getHttpServletRequest(), getHttpServletResponse());
        return authenticationToken;
    }
    /** @return any X509Certificate the client has provided */
    public X509Certificate getX509CertificateFromRequest() {
        if (raAuthenticationHelper==null) {
            raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession, raMasterApi);
        }
        x509Certificate = raAuthenticationHelper.getX509CertificateFromRequest(getHttpServletRequest());
        return x509Certificate;
    }

    public boolean isCertificateInRequest() {
        return getX509CertificateFromRequest() != null;
    }

    public void resetAuthentication(){
        raAuthenticationHelper.resetAuthenticationToken();
    }
    
    private HttpServletRequest getHttpServletRequest() {
        return (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    }

    private HttpServletResponse getHttpServletResponse() {
        return (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse();
    }
    
    public boolean isPublicUser() {
        return getAuthenticationToken() instanceof PublicAccessAuthenticationToken;
    }

    public boolean isOauthUser() {
        return getAuthenticationToken() instanceof OAuth2AuthenticationToken;
    }

    public boolean isClientCertificateUser() {
        return getAuthenticationToken() instanceof X509CertificateAuthenticationToken;
    }

    public String getUserDisplayName() {
        final AuthenticationToken authToken = getAuthenticationToken();
        if (authToken instanceof X509CertificateAuthenticationToken) {
            final Certificate cert = ((X509CertificateAuthenticationToken)authToken).getCertificate();
            final String subjectDN = CertTools.getSubjectDN(cert);
            String cn = CertTools.getPartFromDN(subjectDN, "CN"); // should perhaps be configurable?
            if (cn != null) {
                cn = cn.trim();
                if (!cn.isEmpty()) {
                    return cn;
                }
            }
            return subjectDN;
        } else if (authToken instanceof OAuth2AuthenticationToken) {
            final Set<? extends Principal> principals = authToken.getPrincipals();
            if (CollectionUtils.isNotEmpty(principals)) {
                final Principal principal = principals.iterator().next();
                if (principal instanceof OAuth2Principal) {
                    return ((OAuth2Principal)principal).getDisplayName();
                }
            }
        }
        return authToken.toString();
    }
    
    /** Invoked from RaHttpSessionListener when a session expires/is destroyed */
    public void onSessionDestroyed(final HttpSessionEvent httpSessionEvent) {
        log.info("HTTP session from client with authentication " + authenticationToken + " ended.");
        if (log.isDebugEnabled()) {
            log.debug("HTTP session from client with authentication " + authenticationToken + " ended. jsessionid=" + httpSessionEvent.getSession().getId());
        }
        // Insert additional clean up (if any) needed on logout.
        // (Note that FacesContext is not available any more, but injected SSBs or bean fetched via httpSessionEvent.getSession().getAttribute("beanName") still can be used.)
    }

    /** log out */
    public void logOut() throws IOException {
        if (isOauthUser()) {
            final OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) getAuthenticationToken();
            OAuthConfiguration oAuthConfiguration = raMasterApi.getGlobalConfiguration(OAuthConfiguration.class);
            OAuthKeyInfo oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel(authToken.getProviderLabel());
            if(oAuthKeyInfo != null) {
                // First we invalidate the current session on the server side, so the old session cookie cannot be used again.
                // Will trigger audit log event by CaHttpSessionListner
                HttpServletRequest request = getHttpServletRequest();
                HttpServletResponse response = getHttpServletResponse();
                request.getSession().invalidate();
                // Next, we ask the browser to remove the cookie (a sneaky client can refuse to comply)
                final Cookie killCookie = new Cookie(SESSIONCOOKIENAME, "");
                killCookie.setMaxAge(0);
                killCookie.setPath(request.getContextPath());
                // JsessionID cookies that we can logout are always secure, and we only login over https, so do the same for logout
                killCookie.setHttpOnly(true);
                killCookie.setSecure(true);
                response.addCookie(killCookie);
                String postLogoutRedirectUrl = getRedirectUri();
                String oAuthLogoutUrl = oAuthKeyInfo.getLogoutUrl();
                UriBuilder uriBuilder = UriBuilder.fromUri(oAuthLogoutUrl);
                uriBuilder.queryParam("post_logout_redirect_uri", postLogoutRedirectUrl);
                oAuthLogoutUrl = uriBuilder.build().toString();
                response.sendRedirect(oAuthLogoutUrl);
            }
        }
    }

    private String getRedirectUri() {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        String baseUrl = globalConfiguration.getBaseUrl(
                "https",
                WebConfiguration.getHostName(),
                WebConfiguration.getPublicHttpsPort()
        ) + "ra/";
        return baseUrl + "logout.xhtml";
    }

    public String getUserRemoteAddr() {
        return getHttpServletRequest().getRemoteAddr();
    }
}
