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
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Servlet filter implementation that can use a certificate belonging to a user in EJBCA
 * to emulate SSL client certificate authentication.
 * 
 * @version $Id$
 */
public class ProxiedAuthenticationFilter implements Filter {

	private static final String ATTR_X509CERTIFICATE = "javax.servlet.request.X509Certificate";
    private static final String ATTR_PROXIED_AUTH_TOKEN_STRING = "proxiedAuthenticationTokenString";
	private static final Logger log = Logger.getLogger(ProxiedAuthenticationFilter.class);
	
	private boolean proxiedAuthenticationEnabled = false;
	
	@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
	    proxiedAuthenticationEnabled = WebConfiguration.isProxiedAuthenticationEnabled();
	}

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain filterChain) throws IOException, ServletException {
		if (request.getAttribute(ATTR_X509CERTIFICATE) == null) {
			if (proxiedAuthenticationEnabled) {
				final String username = (String) request.getAttribute(ATTR_PROXIED_AUTH_TOKEN_STRING);
				if (username != null) {
				    final EjbLocalHelper ejb = new EjbLocalHelper();
				    if (log.isDebugEnabled()) {
	                    log.debug("No client certificate supplied through SSL/TLS. Trying alternative certificate emulation lookup for subject '" + username + "'.");
				    }
					final Collection<Certificate> userCerts = ejb.getCertificateStoreSession().findCertificatesByUsernameAndStatus(username, CertificateConstants.CERT_ACTIVE);
					Date latestestIssuance = null;
					final X509Certificate[] tempCerts = new X509Certificate[1];
					for (final Certificate cert : userCerts) {
						if (cert instanceof X509Certificate) {
							final Date thisIssuance = ((X509Certificate)cert).getNotBefore();
							if (latestestIssuance == null || latestestIssuance.after(thisIssuance)) {
								latestestIssuance = thisIssuance;
								tempCerts[0] = (X509Certificate) cert;
							}
						}
					}
					if (tempCerts[0] == null) {
					    final String msg = "Authentication failed. No certificate found for admin with subject '"+username+"'.";
					    log.info(msg);
					    showError((HttpServletResponse)response, msg);
					    return;
					} else {
	                    // Create a temporary Admin/AuthenticationToken to make sure it is NOT authorized with Superadmin rights.
	                    final AuthenticationToken admin = new X509CertificateAuthenticationToken(tempCerts[0]);
	                    if (ejb.getAccessControlSession().isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource()) ||
	                            ejb.getAccessControlSession().isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
	                        final String msg = "Authentication failed. Superadmin login is only allowed using client certificate. Subject was '"+username+"'.";
	                        log.info(msg);
	                        showError((HttpServletResponse)response, msg);
	                        return;
	                    } else {
	                        log.info("Using client certificate emulation for subject '" + username + "'.");
	                        request.setAttribute(ATTR_X509CERTIFICATE, tempCerts);
	                    }
					}
				}
			}
		}
    	filterChain.doFilter(request, response);
	}
	
	private void showError(final HttpServletResponse httpServletResponse, final String content) throws IOException {
        httpServletResponse.setContentType("text/html; charset=UTF-8");
        httpServletResponse.setHeader("pragma", "no-cache");
        httpServletResponse.setHeader("cache-control", "no-cache");
        httpServletResponse.setHeader("expires", "-1");
        httpServletResponse.setContentLength(content.length());
        final OutputStream os = httpServletResponse.getOutputStream();
        os.write(content.getBytes());
        os.flush();
        os.close();
	}
}
