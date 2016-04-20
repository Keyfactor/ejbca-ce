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
import java.security.cert.Certificate;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionEvent;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;

/**
 * JSF Managed Bean for handling authentication of clients.
 * 
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class RaAuthenticationBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaAuthenticationBean.class);

    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;

    private RaAuthenticationHelper raAuthenticationHelper = null;
    private AuthenticationToken authenticationToken = null;

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    public AuthenticationToken getAuthenticationToken() {
        if (raAuthenticationHelper==null) {
            raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession);
        }
        authenticationToken = raAuthenticationHelper.getAuthenticationToken(getHttpServletRequest(), getHttpServletResponse());
        return authenticationToken;
    }
    
    private HttpServletRequest getHttpServletRequest() {
        return (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    }

    private HttpServletResponse getHttpServletResponse() {
        return (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse();
    }
    
    public boolean isPublicUser() {
        final AuthenticationToken authToken = getAuthenticationToken();
        return authToken instanceof PublicAccessAuthenticationToken;
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
}
