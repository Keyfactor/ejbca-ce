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
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;

/**
 * Web session authentication helper.
 * 
 * @version $Id$
 */
public class RaAuthenticationHelper implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(RaAuthenticationHelper.class);

    private final WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    private AuthenticationToken authenticationToken = null;
    private String authenticationTokenTlsSessionId = null;
    private String x509AuthenticationTokenFingerprint = null;

    public RaAuthenticationHelper(final WebAuthenticationProviderSessionLocal webAuthenticationProviderSession) {
        this.webAuthenticationProviderSession = webAuthenticationProviderSession;
    }

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    public AuthenticationToken getAuthenticationToken(final HttpServletRequest httpServletRequest) {
        final String currentTlsSessionId = getTlsSessionId(httpServletRequest);
        if (authenticationToken==null || !StringUtils.equals(authenticationTokenTlsSessionId, currentTlsSessionId)) {
            // Set the current TLS session 
            authenticationTokenTlsSessionId = currentTlsSessionId;
            final X509Certificate x509Certificate = getClientX509Certificate(httpServletRequest);
            if (x509Certificate == null && x509AuthenticationTokenFingerprint!=null) {
                log.warn("Suspected session hijacking attempt from " + httpServletRequest.getRemoteAddr() +
                        ". RA client presented no TLS certificate in HTTP session previously authenticated with client certificate.");
                authenticationToken = null;
                x509AuthenticationTokenFingerprint = null;
            }
            if (x509Certificate != null) {
                final String fingerprint = CertTools.getFingerprintAsString(x509Certificate);
                if (x509AuthenticationTokenFingerprint!=null) {
                    final X509Certificate authenticatedCert = ((X509CertificateAuthenticationToken)authenticationToken).getCertificate();
                    if (!StringUtils.equals(CertTools.getFingerprintAsString(authenticatedCert), x509AuthenticationTokenFingerprint)) {
                        log.warn("Suspected session hijacking attempt from " + httpServletRequest.getRemoteAddr() +
                                ". RA client presented a different TLS certificate in the same HTTP session." +
                                " new certificate had subject '" + CertTools.getSubjectDN(x509Certificate) + "'.");
                        authenticationToken = null;
                        x509AuthenticationTokenFingerprint = null;
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("RA client presented client TLS certificate with subject DN '" + CertTools.getSubjectDN(x509Certificate) + "'.");
                }
                // No need to perform re-authentication if the client certificate was the same
                if (authenticationToken==null) {
                    final AuthenticationSubject subject = new AuthenticationSubject(null, new HashSet<X509Certificate>( Arrays.asList(new X509Certificate[]{ x509Certificate })));
                    authenticationToken = webAuthenticationProviderSession.authenticate(subject);
                }
                x509AuthenticationTokenFingerprint = authenticationToken==null ? null : fingerprint;
            }
            if (authenticationToken == null) {
                authenticationToken = new PublicAccessAuthenticationToken("Public access from " + httpServletRequest.getRemoteAddr());
            }
        }
        return authenticationToken;
    }
    
    private X509Certificate getClientX509Certificate(final HttpServletRequest httpServletRequest) {
        final X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("javax.servlet.request.X509Certificate");
        return certificates == null || certificates.length==0 ? null : certificates[0];
    }
    
    private String getTlsSessionId(final HttpServletRequest httpServletRequest) {
        final String sslSessionIdServletsStandard = (String)httpServletRequest.getAttribute("javax.servlet.request.ssl_session_id");
        final String sslSessionIdJBoss7 = (String)httpServletRequest.getAttribute("javax.servlet.request.ssl_session");
        return sslSessionIdJBoss7==null ? sslSessionIdServletsStandard : sslSessionIdJBoss7;
    }
}
