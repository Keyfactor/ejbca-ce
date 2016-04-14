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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet for download of CA certificates and chains.
 * 
 * @version $Id$
 */
@WebServlet("/cert")
public class RaCertDistServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaCertDistServlet.class);
    private static final String PARAMETER_CAID = "caid";
    private static final String PARAMETER_FINGERPRINT = "fp";
    private static final String PARAMETER_FORMAT = "format";
    private static final String PARAMETER_FORMAT_OPTION_FIREFOX = "ns";
    private static final String PARAMETER_FORMAT_OPTION_PEM = "pem";    // Applies to both certificate chain and individual certificates download
    private static final String PARAMETER_FORMAT_OPTION_DER = "der";
    private static final String PARAMETER_FORMAT_OPTION_JKS = "jks";    // Applies only to certificate chain download
    private static final String PARAMETER_CHAIN = "chain";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;

    private RaAuthenticationHelper raAuthenticationHelper = null;

    @Override
    protected void service(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws ServletException, IOException {
        if (raAuthenticationHelper==null) {
            // Initialize the authentication helper function
            raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession);
        }
        final boolean fullChain = Boolean.valueOf(httpServletRequest.getParameter(PARAMETER_CHAIN));
        if (httpServletRequest.getParameter(PARAMETER_CAID) != null) {
            List<Certificate> chain = null;
            try {
                final int caId = Integer.valueOf(httpServletRequest.getParameter(PARAMETER_CAID));
                final AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpServletRequest, httpServletResponse);
                final List<CAInfo> caInfos = raMasterApi.getAuthorizedCas(authenticationToken);
                if (log.isDebugEnabled()) {
                    log.debug(authenticationToken.toString() + " was authorized to " + caInfos.size() + " CAs.");
                }
                for (final CAInfo caInfo : caInfos) {
                    if (caId == caInfo.getCAId()) {
                        chain = new ArrayList<>(caInfo.getCertificateChain());
                        break;
                    }
                }
            } catch (NumberFormatException e) {
                log.debug("Unable to parse " + PARAMETER_CAID + " request parameter: " + e.getMessage());
            }
            if (chain==null) {
                httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to parse " + PARAMETER_CAID + " request parameter.");
                return;
            } else {
                try {
                    final Certificate caCertificate = chain.get(0);
                    String filename = RequestHelper.getFileNameFromCertNoEnding(caCertificate, "ca");
                    String contentType = "application/octet-stream";
                    byte[] response = null;
                    if (fullChain) {
                        switch (httpServletRequest.getParameter(PARAMETER_FORMAT)) {
                        case PARAMETER_FORMAT_OPTION_JKS: {
                            // Create a JKS truststore with the CA certificates in
                            final KeyStore keyStore = KeyStore.getInstance("JKS");
                            keyStore.load(null, null);
                            for (int i=0; i<chain.size(); i++) {
                                final String subjectDn = CertTools.getSubjectDN(chain.get(i));
                                String alias = CertTools.getPartFromDN(subjectDn, "CN");
                                if (alias == null) {
                                    alias = CertTools.getPartFromDN(subjectDn, "O");
                                }
                                if (alias == null) {
                                    alias = "cacert"+i;
                                }
                                alias.replaceAll(" ", "_").substring(0, Math.min(15, alias.length()));
                                keyStore.setCertificateEntry(alias, chain.get(i));
                            }
                            try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
                                keyStore.store(out, "changeit".toCharArray());
                                response = out.toByteArray();
                            }
                            filename += "-chain.jks";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_PEM:
                        default: {
                            response = CertTools.getPemFromCertificateChain(chain);
                            filename += "-chain.pem";
                            break;
                        }
                        }
                    } else {
                        response = caCertificate.getEncoded();
                        switch (httpServletRequest.getParameter(PARAMETER_FORMAT)) {
                        case PARAMETER_FORMAT_OPTION_FIREFOX: {
                            filename = null;
                            contentType = "application/x-x509-ca-cert";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_DER: {
                            filename += (caCertificate instanceof CardVerifiableCertificate) ? ".cvcert" : ".crt";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_PEM:
                        default: {
                            filename += ".pem";
                            response = CertTools.getPemFromCertificateChain(Arrays.asList(new Certificate[]{ caCertificate }));
                            break;
                        }
                        }
                    }
                    writeResponseBytes(httpServletResponse, filename, contentType, response);
                } catch (NoSuchFieldException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                    httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to serve request due to internal error.");
                    return;
                }
            }
        } else if (httpServletRequest.getParameter(PARAMETER_FINGERPRINT) != null) {
            // Placeholder for serving regular leaf certificate (optionally with full chain) 
            if (fullChain) {
                
            } else {
                
            }
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to parse " + PARAMETER_FINGERPRINT + " request parameter.");
        } else {
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to request parameters.");
        }
    }

    private void writeResponseBytes(final HttpServletResponse httpServletResponse, final String filename, final String contentType, final byte[] response) throws IOException {
        ServletUtils.removeCacheHeaders(httpServletResponse);
        if (filename!=null) {
            httpServletResponse.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        }
        httpServletResponse.setContentType(contentType);
        httpServletResponse.setContentLength(response.length);
        httpServletResponse.getOutputStream().write(response);
    }
}
