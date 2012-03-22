/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.integrated.IntegratedOcspResponseGeneratorSessionLocal;
import org.cesecore.config.ConfigurationHolder;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.HTMLTools;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 *
 * @version  $Id$
 */
public class OCSPServlet extends BaseOcspServlet {

    private static final long serialVersionUID = 8081630219584820112L;
    private static final Logger log = Logger.getLogger(OCSPServlet.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private IntegratedOcspResponseGeneratorSessionLocal integratedOcspResponseGeneratorSession;

    @Override
    public Logger getLogger() {
        return log;
    }

    @Override
    protected void reloadKeys() throws AuthorizationDeniedException {
        integratedOcspResponseGeneratorSession.reloadTokenAndChainCache();
        
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Logger log = getLogger();
        try {
            
            if (log.isTraceEnabled()) {
                log.trace(">doGet()");
            }
            // We have a command to force reloading of keys that can only be run from localhost
            final boolean doReload = StringUtils.equals(request.getParameter("reloadkeys"), "true");
            final String newConfig = request.getParameter("newConfig");
            final boolean doNewConfig = newConfig != null && newConfig.length() > 0;
            final boolean doRestoreConfig = request.getParameter("restoreConfig") != null;
            final String remote;
            if (doReload || doNewConfig || doRestoreConfig) {
                remote = request.getRemoteAddr();
                if (!StringUtils.equals(remote, "127.0.0.1")) {
                    log.info("Got reloadkeys or updateConfig of restoreConfig command from unauthorized ip: " + remote);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            } else {
                remote = null;
            }
            if (doReload) {
                log.info(intres.getLocalizedMessage("ocsp.reloadkeys", remote));
                // Reload CA certificates
                integratedOcspResponseGeneratorSession.reloadTokenAndChainCache();
                return;
            }
            if (doNewConfig) {
                final String aConfig[] = newConfig.split("\\|\\|");
                for (int i = 0; i < aConfig.length; i++) {
                    log.debug("Config change: " + aConfig[i]);
                    final int separatorIx = aConfig[i].indexOf('=');
                    if (separatorIx < 0) {
                        ConfigurationHolder.updateConfiguration(aConfig[i], null);
                        continue;
                    }
                    ConfigurationHolder.updateConfiguration(aConfig[i].substring(0, separatorIx),
                            aConfig[i].substring(separatorIx + 1, aConfig[i].length()));
                }
                OcspConfigurationCache.INSTANCE.reloadConfiguration();
                log.info("Call from " + remote + " to update configuration");
                return;
            }
            if (doRestoreConfig) {
                ConfigurationHolder.restoreConfiguration();
                OcspConfigurationCache.INSTANCE.reloadConfiguration();
                log.info("Call from " + remote + " to restore configuration.");
                return;
            }
            processOcspRequest(request, response);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<doGet()");
            }
        }
    } // doGet

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Logger log = getLogger();
        if (log.isTraceEnabled()) {
            log.trace(">doPost()");
        }
        try {
            final String contentType = request.getHeader("Content-Type");
            if (contentType != null && contentType.equalsIgnoreCase("application/ocsp-request")) {
                processOcspRequest(request, response);
                return;
            }
            if (contentType != null) {
                final String sError = "Content-type is not application/ocsp-request. It is \'" + HTMLTools.htmlescape(contentType) + "\'.";
                log.debug(sError);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, sError);
                return;
            }
            final String remoteAddr = request.getRemoteAddr();
            if (!remoteAddr.equals("127.0.0.1")) {
                final String sError = "You have connected from \'" + remoteAddr + "\'. You may only connect from 127.0.0.1";
                log.debug(sError);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, sError);
                return;
            }
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<doPost()");
            }
        }
    } //doPost
    
    @Override
    protected OcspResponseGeneratorSessionLocal getOcspResponseGenerator() {
        return integratedOcspResponseGeneratorSession;
    }

    
   
}
