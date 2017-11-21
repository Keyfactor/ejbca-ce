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
package org.ejbca.ui.web.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet implementing server side of the Certificate Management Protocols (CMP)
 * 
 * @version $Id$
 */
public class CmpServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CmpServlet.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String DEFAULT_CMP_ALIAS = "cmp";
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    /**
     * Handles HTTP post
     * 
     * @param request java standard arg
     * @param response java standard arg
     * 
     * @throws IOException input/output error
     */
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">doPost()");
        }
        boolean protocolEnabled = ((AvailableProtocolsConfiguration)globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID)).
                getProtocolStatus(AvailableProtocols.CMP.getName());
        try {
            if (!protocolEnabled) {
                log.info("CMP Protocol is disabled");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "CMP is disabled");
                return;
            }
            final String alias = getAlias(request.getPathInfo());
            if(alias.length() > 32) {
                log.info("Unaccepted alias more than 32 characters.");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unaccepted alias more than 32 characters.");
                return;
            }
            final ServletInputStream sin = request.getInputStream();
            // This small code snippet is inspired/copied by apache IO utils to Tomas Gustavsson...
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final byte[] buf = new byte[1024];
            int n = 0;
            int bytesRead = 0;
            while (-1 != (n = sin.read(buf))) {
                bytesRead += n;
                if (bytesRead > LimitLengthASN1Reader.MAX_REQUEST_SIZE) {
                    throw new IllegalArgumentException("Request is larger than "+LimitLengthASN1Reader.MAX_REQUEST_SIZE+" bytes.");
                }
                output.write(buf, 0, n);
            }
            service(output.toByteArray(), request.getRemoteAddr(), response, alias);
        } catch (IOException | RuntimeException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            log.info(intres.getLocalizedMessage("cmp.errornoasn1"), e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<doPost()");
        }
    }

    /**
     * Handles HTTP get
     * 
     * @param request java standard arg
     * @param response java standard arg
     * 
     * @throws IOException input/output error
     */
    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">doGet()");
        }
        log.info("Received un-allowed method GET in CMP servlet: query string=" + request.getQueryString());
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
        if (log.isTraceEnabled()) {
            log.trace("<doGet()");
        }
    }

    private void service(final byte[] pkiMessageBytes, final String remoteAddr, final HttpServletResponse response, String alias) throws IOException {
        try {
            log.info(intres.getLocalizedMessage("cmp.receivedmsg", remoteAddr, alias));
            final long startTime = System.currentTimeMillis();
            byte[] result = null;
            try {
                final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal("CmpServlet", remoteAddr));
                result = raMasterApiProxyBean.cmpDispatch(authenticationToken, pkiMessageBytes, alias);
            } catch (NoSuchAliasException e) {
                // The CMP alias does not exist
                response.sendError(HttpServletResponse.SC_NOT_FOUND, e.getMessage());
                log.info(e.getMessage(), e);
                return;
            }
            if (result == null) {
                // If resp is null, it means that the dispatcher failed to process the message.
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, intres.getLocalizedMessage("cmp.errornullresp"));
                return;
            }
            // Add no-cache headers as defined in 
            // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
            ServletUtils.addCacheHeaders(response);
            // Send back CMP response
            RequestHelper.sendBinaryBytes(result, response, "application/pkixcmp", null);
            final long endTime = System.currentTimeMillis();
            log.info(intres.getLocalizedMessage("cmp.sentresponsemsg", remoteAddr, Long.valueOf(endTime - startTime)));
        } catch (IOException | RuntimeException e) {
            log.error("Error in CmpServlet:", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
    
    private String getAlias(final String pathInfo) {
        // PathInfo contains the alias used for CMP configuration. 
        // The CMP URL for custom configuration looks like: http://HOST:PORT/ejbca/publicweb/cmp/*
        // pathInfo contains what * is and should have the form "/<SOME IDENTIFYING TEXT>". We extract the "SOME IDENTIFYING 
        // TEXT" and that will be the CMP configuration alias.
        final String alias;
        if (pathInfo!=null && pathInfo.length()>1) {
            alias = pathInfo.substring(1);
            if (log.isDebugEnabled()) {
                log.debug("Using CMP configuration alias: " + alias);
            }
        } else {
            alias = DEFAULT_CMP_ALIAS;
            if (log.isDebugEnabled()) {
                log.debug("No CMP alias specified in the URL. Using the default alias: " + DEFAULT_CMP_ALIAS);
            }
        }
        return alias;
    }
}
