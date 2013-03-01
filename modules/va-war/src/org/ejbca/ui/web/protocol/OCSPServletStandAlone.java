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
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorSessionLocal;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ocsp.standalone.OcspKeyRenewalSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.HTMLTools;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 *
 * @version  $Id$
 */
public class OCSPServletStandAlone extends BaseOcspServlet {

    private static final long serialVersionUID = -7093480682721604160L;
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** Special logger only used to log version number. ejbca.version.log can be directed to a special logger, or have a special log level 
     * in the log4j configuration. 
     */
    private static final Logger m_versionLog = Logger.getLogger("org.ejbca.version.log");

    private static final Logger log = Logger.getLogger(OCSPServletStandAlone.class);
    private final Set<String> rekeyingTriggeringHosts = OcspConfiguration.getRekeyingTriggingHosts();
    private final String rekeyingTriggingPassword = OcspConfiguration.getRekeyingTriggingPassword();

    @EJB
    private StandaloneOcspResponseGeneratorSessionLocal standaloneOcspResponseGeneratorSession;
    @EJB
    private OcspKeyRenewalSessionLocal ocspKeyRenewalSession;

    @Override
    public void init(ServletConfig config) throws ServletException {

        // Log with warn priority so it will be visible in strict production configurations  
	    m_versionLog.warn("Init, "+GlobalConfiguration.EJBCA_VERSION+" OCSP startup");
	    if (!OcspConfiguration.getDoNotStorePasswordsInMemory()) {
            standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache();
        } 
    }
    
    /**
     * Method used to log OCSP service shutdown.
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy() {
		super.destroy();
        // Log with warn priority so it will be visible in strict production configurations  
	    m_versionLog.warn("Destroy, "+GlobalConfiguration.EJBCA_VERSION+" OCSP shutdown");
	}


    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Logger log = getLogger();
        try {
            
            if (log.isTraceEnabled()) {
                log.trace(">doGet()");
            }
            final String keyRenewalSignerDN =  request.getParameter("renewSigner");
            final boolean performKeyRenewal = keyRenewalSignerDN!=null && keyRenewalSignerDN.length()>0;
            
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
             
                if (!OcspConfiguration.getDoNotStorePasswordsInMemory()) {
                    standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache();
                }
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
            if ( performKeyRenewal ) {
                if ( !this.rekeyingTriggeringHosts.contains(remote) ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.unauthorized.ip", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                if ( this.rekeyingTriggingPassword==null ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.not.enabled",remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                final String requestPassword = request.getParameter("password");
                final String keyrenewalSignerDn =  request.getParameter("renewSigner");
                if ( !this.rekeyingTriggingPassword.equals(requestPassword) ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.wrong.password", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                try {
                    renewKeyStore(keyrenewalSignerDn);
                } catch (KeyStoreException e) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.keystore.notactivated", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (CryptoTokenOfflineException e) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.cryptotoken.notactivated", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (InvalidKeyException e) {                   
                    log.info( intres.getLocalizedMessage("ocsp.rekey.invalid.key", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
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
            final String password = request.getHeader("activate");
            if (password == null) {
                final String sError = "No \'Content-Type\' or \'activate\' property in request.";
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
            
            try {
                standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache(password);
            } catch (Exception e) {
                log.error("Problem loading keys.", e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Problem. See ocsp responder server log.");
            }
            
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<doPost()");
            }
        }
    } //doPost

    @Override
    protected void reloadKeys() throws AuthorizationDeniedException {
        standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache();
    }
    
    /**
     * Manually renews this OCSP responder's keystores.
     * @throws KeyStoreException if key store hasn't been activated.
     * @throws CryptoTokenOfflineException 
     * @throws InvalidKeyException if the public key can not be used to verify a string signed by the private key, because the key is wrong or the 
     * signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws CertificateException 
     */
    public void renewKeyStore(String keyrenewalSignerDn) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException {
       
        ocspKeyRenewalSession.renewKeyStores(keyrenewalSignerDn);
    }

    @Override
    protected OcspResponseGeneratorSessionLocal getOcspResponseGenerator() {
        return standaloneOcspResponseGeneratorSession;
    }

    

}
