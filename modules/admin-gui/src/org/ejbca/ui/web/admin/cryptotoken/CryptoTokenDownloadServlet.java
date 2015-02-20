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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.IOException;
import java.security.PublicKey;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;

/**
 * Servlet for download of CryptoToken related files, such as the the public key as PEM for a key pair.
 * 
 * @version $Id$
 */
public class CryptoTokenDownloadServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CryptoTokenDownloadServlet.class);
    //private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final AuthenticationToken alwaysAllowAuthenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CryptoTokenDownloadServlet"));

    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;

    // org.cesecore.keys.util.KeyTools.getAsPem(PublicKey)
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    /** Handles HTTP POST the same way HTTP GET is handled. */
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        doGet(request, response);
    }

    /** Handles HTTP GET */
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        log.trace(">doGet()");
        final String cryptoTokenIdParam = request.getParameter("cryptoTokenId");
        final int cryptoTokenId = Integer.parseInt(cryptoTokenIdParam);
        final String aliasParam = request.getParameter("alias");
        try {
            final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(alwaysAllowAuthenticationToken, cryptoTokenId, aliasParam).getPublicKey();
            response.setContentType("application/octet-stream");
            response.setHeader("Content-disposition", " attachment; filename=\"" + StringTools.stripFilename(aliasParam + ".pem") + "\"");
            response.getOutputStream().write(KeyTools.getAsPem(publicKey).getBytes());
            response.flushBuffer();
        } catch (CryptoTokenOfflineException e) {
            throw new ServletException(e);
        } catch (AuthorizationDeniedException e) {
            throw new ServletException(e);
        }
        log.trace("<doGet()");
    }   
}
