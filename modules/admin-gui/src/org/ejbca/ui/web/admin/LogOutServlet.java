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
package org.ejbca.ui.web.admin;

import java.io.IOException;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.util.HttpTools;

/**
 * Servlet for invalidation of the current HTTP session.
 *
 */
public class LogOutServlet extends HttpServlet {
    private static Logger logger = Logger.getLogger(LogOutServlet.class);

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private WebAuthenticationProviderSessionLocal authenticationSession;
    
    private static final long serialVersionUID = 1L;
    
    // JavaServlet Specification 2.5 Section 7.1.1: "...The name of the session tracking cookie must be JSESSIONID".
    private static final String SESSIONCOOKIENAME = "JSESSIONID";
    private GlobalConfiguration globalConfiguration;
    
    @PostConstruct
    public void initialize() {
        globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }
    
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
    	doGet(request, response);
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        final String bearerToken = getBearerToken(request);
        OAuthKeyInfo oAuthKeyInfo = null;
        if (!StringUtils.isEmpty(bearerToken)) {
            OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession
                    .getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
            try {
                AuthenticationToken authenticationToken = authenticationSession.authenticateUsingOAuthBearerToken(oAuthConfiguration, bearerToken);
                if (authenticationToken == null) {
                    logger.debug("Bearer token authentication failed in logout.");
                } else {
                    OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authenticationToken;
                    oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel(token.getProviderLabel());
                }
            } catch (TokenExpiredException e) {
                //do nothing
            }
        }
        // First we invalidate the current session on the server side, so the old session cookie cannot be used again.
        // Will trigger audit log event by CaHttpSessionListner
        request.getSession().invalidate();
        // Next, we ask the browser to remove the cookie (a sneaky client can refuse to comply)
        final Cookie killCookie = new Cookie(SESSIONCOOKIENAME, "");
        killCookie.setMaxAge(0);
        killCookie.setPath(request.getContextPath());
        // JsessionID cookies that we can logout are always secure, and we only login over https, so do the same for logout
        killCookie.setHttpOnly(true);
        killCookie.setSecure(true);
        response.addCookie(killCookie);
        if (oAuthKeyInfo != null) {
            String postLogoutRedirectUrl = getRedirectUri();
            String oAuthLogoutUrl = oAuthKeyInfo.getLogoutUrl();
            UriBuilder uriBuilder = UriBuilder.fromUri(oAuthLogoutUrl);
            uriBuilder.queryParam("post_logout_redirect_uri", postLogoutRedirectUrl);
            oAuthLogoutUrl = uriBuilder.build().toString();
            response.sendRedirect(oAuthLogoutUrl);
        } else {
            if (WebConfiguration.isProxiedAuthenticationEnabled()) {
                // Redirect user to "/logout" that can be handled by a authentication proxy
                response.sendRedirect("/logout");
            } else {
                // Redirect user to public RA Web pages to avoid initializing a new AdminGUI session.
                response.sendRedirect(globalConfiguration.getRelativeUri() + "ra/logout.xhtml");
            }
        }
    }

    private String getBearerToken(HttpServletRequest httpServletRequest) {
        String oauthBearerToken = HttpTools.extractBearerAuthorization(httpServletRequest.getHeader(HttpTools.AUTHORIZATION_HEADER));
        if (oauthBearerToken == null) {
            oauthBearerToken = (String) httpServletRequest.getSession(true).getAttribute("ejbca.bearer.token");
        }
        return oauthBearerToken;
    }

    private String getRedirectUri() {
        String baseUrl = globalConfiguration.getBaseUrl(
                "https",
                WebConfiguration.getHostName(),
                WebConfiguration.getPublicHttpsPort()
        ) + "ra/";
        return baseUrl + "logout.xhtml";
    }
}
