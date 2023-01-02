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

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.util.HttpTools;

/**
 * Web session authentication helper.
 *
 */
public class RaAuthenticationHelper implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(RaAuthenticationHelper.class);
    private static final String HTTP_HEADER_SET_COOKIE = "Set-Cookie";
    private static final String HTTP_HEADER_X_POWERED_BY = "X-Powered-By";

    private final WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    private final RaMasterApiProxyBeanLocal raMasterApi;
    private AuthenticationToken authenticationToken = null;
    private String authenticationTokenTlsSessionId = null;
    private String x509AuthenticationTokenFingerprint = null;

    public RaAuthenticationHelper(final WebAuthenticationProviderSessionLocal webAuthenticationProviderSession, final RaMasterApiProxyBeanLocal raMasterApi) {
        this.webAuthenticationProviderSession = webAuthenticationProviderSession;
        this.raMasterApi = raMasterApi;
    }

    public void resetAuthenticationToken(){
        authenticationToken = null;
    }

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    public AuthenticationToken getAuthenticationToken(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        final String currentTlsSessionId = getTlsSessionId(httpServletRequest);
        if (authenticationToken==null || !StringUtils.equals(authenticationTokenTlsSessionId, currentTlsSessionId)) {
            if (log.isTraceEnabled()) {
                log.trace("New TLS session IDs or authenticationToken: currentClientTlsSessionID: "+currentTlsSessionId+", authenticationTokenTlsSessionId: "+authenticationTokenTlsSessionId);
            }
            // Set the current TLS session 
            authenticationTokenTlsSessionId = currentTlsSessionId;
            final X509Certificate x509Certificate = getClientX509Certificate(httpServletRequest);
            final String oauthBearerToken = getBearerToken(httpServletRequest);
            if (x509Certificate == null && x509AuthenticationTokenFingerprint != null) {
                log.warn("Suspected session hijacking attempt from " + httpServletRequest.getRemoteAddr() +
                        ". RA client presented no TLS certificate in HTTP session previously authenticated with client certificate.");
                authenticationToken = null;
                x509AuthenticationTokenFingerprint = null;
            }
            if (x509Certificate != null) {
                final String fingerprint = CertTools.getFingerprintAsString(x509Certificate);
                if (log.isTraceEnabled()) {
                    log.trace("currentRequestFingerprint: "+fingerprint+", x509AuthenticationTokenFingerprint: "+x509AuthenticationTokenFingerprint);
                }
                if (x509AuthenticationTokenFingerprint != null && !StringUtils.equals(fingerprint, x509AuthenticationTokenFingerprint)) {
                    log.warn("Suspected session hijacking attempt from " + httpServletRequest.getRemoteAddr() +
                            ". RA client presented a different TLS certificate in the same HTTP session." +
                            " new certificate had subject '" + CertTools.getSubjectDN(x509Certificate) + "'.");
                    authenticationToken = null;
                    x509AuthenticationTokenFingerprint = null;
                }
                if (log.isDebugEnabled()) {
                    log.debug("RA client presented client TLS certificate with subject DN '" + CertTools.getSubjectDN(x509Certificate) + "'.");
                }
                // No need to perform re-authentication if the client certificate was the same
                if (authenticationToken == null) {
                    authenticationToken = webAuthenticationProviderSession.authenticateUsingClientCertificate(x509Certificate);
                }
                if (!isAuthenticationTokenAccepted()) {
                    authenticationToken = null;
                    log.info("Authentication failed using certificate with fingerprint " + fingerprint + " reason: user has no access");
                }
                x509AuthenticationTokenFingerprint = authenticationToken == null ? null : fingerprint;
            }
            if (oauthBearerToken != null && authenticationToken == null) {
                final OAuthConfiguration oauthConfiguration = raMasterApi.getGlobalConfiguration(OAuthConfiguration.class);
                try {
                    authenticationToken = webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(oauthConfiguration, oauthBearerToken);
                } catch (TokenExpiredException e) {
                    String refreshToken = getRefreshToken(httpServletRequest);
                    if (refreshToken != null) {
                        OAuthGrantResponseInfo token = null;
                        try {
                            token = webAuthenticationProviderSession.refreshOAuthBearerToken(oauthConfiguration, oauthBearerToken, refreshToken);
                            if (token != null) {
                                httpServletRequest.getSession(true).setAttribute("ejbca.bearer.token", token.getAccessToken());
                                if (token.getRefreshToken() != null) {
                                    httpServletRequest.getSession(true).setAttribute("ejbca.refresh.token", token.getRefreshToken());
                                }
                                authenticationToken = webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(oauthConfiguration, token.getAccessToken());
                            }
                        } catch (TokenExpiredException tokenExpiredException) {
                            log.info("Authentication failed using OAuth Bearer Token. Token Expired");
                        }
                    }
                }
                if (authenticationToken == null) {
                    log.warn("Authentication failed using OAuth Bearer Token");
                }
            }
            if (authenticationToken == null) {
                // Instead of checking httpServletRequest.isSecure() (connection deemed secure by container), we check if a TLS session is present
                Object cipherSuite = httpServletRequest.getAttribute("javax.servlet.request.cipher_suite");
                final boolean confidentialTransport = cipherSuite != null;
                authenticationToken = webAuthenticationProviderSession.authenticateUsingNothing(httpServletRequest.getRemoteAddr(), confidentialTransport );
            }
        }
        resetUnwantedHttpHeaders(httpServletRequest, httpServletResponse);
        return authenticationToken;
    }
    
    /** @return any X509Certificate the client has provided with the request*/
    public X509Certificate getX509CertificateFromRequest(final HttpServletRequest httpServletRequest) {
        X509Certificate x509Certificate = getClientX509Certificate(httpServletRequest);
        return x509Certificate;
    }

    /** Checks if an authentication token is accepted by the CA. */
    private boolean isAuthenticationTokenAccepted() {
        if (authenticationToken == null) {
            return false;
        } else {
            // If the CA does not return any CAs, then we are unauthorized
            final IdNameHashMap<CAInfo> authorizedCas = raMasterApi.getAuthorizedCAInfos(authenticationToken);
            return authorizedCas != null && !authorizedCas.isEmpty();
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

    /**
     * Gets bearer token from Authorization header or from session
     * @param httpServletRequest
     * @return
     */
    private String getRefreshToken(HttpServletRequest httpServletRequest) {
        return  (String) httpServletRequest.getSession(true).getAttribute("ejbca.refresh.token");
    }
    
    /** Invoke once the session is started to prevent security leak via HTTP headers related. */
    private void resetUnwantedHttpHeaders(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        // Ensure that we never send the JSESSIONID over an insecure (HTTP) connection
        // By default JBoss will send the JSESSIONID cookie over HTTP with the "Secure;" option. Since this is sent in clear from the server to the broswer
        // it does not really help security much that it is only sent over HTTPS from client to server.
        if (!httpServletRequest.isSecure() && !StringUtils.isEmpty(httpServletResponse.getHeader(HTTP_HEADER_SET_COOKIE))) {
            if (log.isDebugEnabled()) {
                log.debug("Preventing '"+HTTP_HEADER_SET_COOKIE+"' HTTP header on insecure connection with value: " + httpServletResponse.getHeader(HTTP_HEADER_SET_COOKIE));
            }
            httpServletResponse.setHeader(HTTP_HEADER_SET_COOKIE, "");
        }
        // Prevent sending the the X-Powered-By header e.g. "JSF/2.0"
        if (!StringUtils.isEmpty(httpServletResponse.getHeader(HTTP_HEADER_X_POWERED_BY))) {
            if (log.isDebugEnabled()) {
                log.debug("Preventing '"+HTTP_HEADER_X_POWERED_BY+"' HTTP header with value: " + httpServletResponse.getHeader(HTTP_HEADER_X_POWERED_BY));
            }
            httpServletResponse.setHeader(HTTP_HEADER_X_POWERED_BY, "");
        }
    }
    
    private X509Certificate getClientX509Certificate(final HttpServletRequest httpServletRequest) {
        final X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("javax.servlet.request.X509Certificate");
        return certificates == null || certificates.length==0 ? null : certificates[0];
    }
    
    private String getTlsSessionId(final HttpServletRequest httpServletRequest) {
        final String sslSessionIdServletsStandard;
        final Object sslSessionIdServletsStandardObject = httpServletRequest.getAttribute("javax.servlet.request.ssl_session_id");
        if (sslSessionIdServletsStandardObject != null && sslSessionIdServletsStandardObject instanceof byte[]) {
            // Wildfly 9 stores the TLS sessions as a raw byte array. Convert it to a hex String.
            sslSessionIdServletsStandard = new String(Hex.encode((byte[]) sslSessionIdServletsStandardObject), StandardCharsets.UTF_8);
        } else {
            sslSessionIdServletsStandard = (String) sslSessionIdServletsStandardObject; 
        }
        final String sslSessionIdJBoss7 = (String)httpServletRequest.getAttribute("javax.servlet.request.ssl_session");
        return sslSessionIdJBoss7==null ? sslSessionIdServletsStandard : sslSessionIdJBoss7;
    }
}
