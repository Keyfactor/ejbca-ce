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
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
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

    private AuthenticationToken authenticationToken = null;

    /** @return the X509CertificateAuthenticationToken if the client has provided a certificate or a PublicAccessAuthenticationToken otherwise. */
    public AuthenticationToken getAuthenticationToken() {
        if (authenticationToken==null) {
            final HttpServletRequest currentRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            final X509Certificate[] certificates = (X509Certificate[]) currentRequest.getAttribute("javax.servlet.request.X509Certificate");
            if (certificates != null && certificates.length>0) {
                final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
                credentials.add(certificates[0]);
                if (log.isDebugEnabled()) {
                    log.debug("RA client provided client TLS certificate with subject DN '" + CertTools.getSubjectDN(certificates[0]) + "'.");
                }
                final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
                authenticationToken = webAuthenticationProviderSession.authenticate(subject);
            }
            if (authenticationToken == null) {
                authenticationToken = new PublicAccessAuthenticationToken("Public access from " + currentRequest.getRemoteAddr());
            }
        }
        return authenticationToken;
    }
}
