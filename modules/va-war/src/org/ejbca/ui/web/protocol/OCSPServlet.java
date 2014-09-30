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

import java.io.IOException;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.GUIDGenerator;
import org.ejbca.core.ejb.ocsp.OcspKeyRenewalSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.util.HTMLTools;
import org.ejbca.util.IPatternLogger;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 *
 * @version  $Id$
 */
public class OCSPServlet extends HttpServlet {

    private static final long serialVersionUID = 8081630219584820112L;
    private static final Logger log = Logger.getLogger(OCSPServlet.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private final String sessionID = GUIDGenerator.generateGUID(this);
    
    @EJB
    private OcspResponseGeneratorSessionLocal integratedOcspResponseGeneratorSession;
    @EJB
    private OcspKeyRenewalSessionLocal ocspKeyRenewalSession;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
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
            final String remote = request.getRemoteAddr();
            if (doReload || doNewConfig || doRestoreConfig) {
                if (!StringUtils.equals(remote, "127.0.0.1")) {
                    log.info("Got reloadkeys or updateConfig of restoreConfig command from unauthorized ip: " + remote);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }
            if (doReload) {
                log.info(intres.getLocalizedMessage("ocsp.reloadkeys", remote));
                // Reload CA certificates
                integratedOcspResponseGeneratorSession.reloadOcspSigningCache();
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
                final Set<String> rekeyingTriggeringHosts = OcspConfiguration.getRekeyingTriggingHosts();
                if ( !rekeyingTriggeringHosts.contains(remote) ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.unauthorized.ip", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                final String rekeyingTriggingPassword = OcspConfiguration.getRekeyingTriggingPassword();
                if ( rekeyingTriggingPassword==null ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.not.enabled",remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                final String requestPassword = request.getParameter("password");
                final String keyrenewalSignerDn =  request.getParameter("renewSigner");
                if ( !rekeyingTriggingPassword.equals(requestPassword) ) {
                    log.info( intres.getLocalizedMessage("ocsp.rekey.triggered.wrong.password", remote) );
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                try {
                    ocspKeyRenewalSession.renewKeyStores(keyrenewalSignerDn);
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
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (log.isTraceEnabled()) {
            log.trace(">doPost()");
        }
        try {
            final String contentType = request.getHeader("Content-Type");
            if (contentType != null && contentType.equalsIgnoreCase("application/ocsp-request")) {
                processOcspRequest(request, response);
                return;
            }
            final String remoteAddr = request.getRemoteAddr();
            // Legacy support for activation using ClientToolBox. We will only use this once for upgrading the installation.
            final String activationPassword = request.getHeader("activate");
            if ( activationPassword!=null && remoteAddr.equals("127.0.0.1")) {
                try {
                    log.warn("'active' will only be used for initial one-time upgrade."+
                            " Use regular CryptoToken activation in EJB CLI or Admin GUI to active your responder keystores.");
                    integratedOcspResponseGeneratorSession.adhocUpgradeFromPre60(activationPassword.toCharArray());
                } catch (Exception e) {
                    log.error("Problem loading keys.", e);
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Problem. See ocsp responder server log.");
                }
                return;
            }
            if (contentType != null) {
                final String sError = "Content-type is not application/ocsp-request. It is \'" + HTMLTools.htmlescape(contentType) + "\'.";
                log.debug(sError);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, sError);
                return;
            }
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
    }

    private void processOcspRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        final String remoteAddress = request.getRemoteAddr();
        final String remoteHost = request.getRemoteHost();
        final StringBuffer requestUrl = request.getRequestURL();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), remoteAddress);
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), remoteAddress);
        try {    
            auditLogger.paramPut(PatternLogger.LOG_ID, Integer.valueOf(localTransactionId));
            auditLogger.paramPut(PatternLogger.SESSION_ID, this.sessionID);
            auditLogger.paramPut(PatternLogger.CLIENT_IP, remoteAddress);
            transactionLogger.paramPut(PatternLogger.LOG_ID, Integer.valueOf(localTransactionId));
            transactionLogger.paramPut(PatternLogger.SESSION_ID, this.sessionID);
            transactionLogger.paramPut(PatternLogger.CLIENT_IP, remoteAddress);
            
            OCSPRespBuilder responseGenerator = new OCSPRespBuilder();
            OcspResponseInformation ocspResponseInformation = null;
            try {
                byte[] requestBytes = checkAndGetRequestBytes(request);
                X509Certificate[] requestCertificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
                ocspResponseInformation = integratedOcspResponseGeneratorSession.getOcspResponse(
                        requestBytes, requestCertificates, remoteAddress, remoteHost, requestUrl, auditLogger, transactionLogger);
            } catch (MalformedRequestException e) {
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
                String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
                log.info(errMsg);
                if (log.isDebugEnabled()) {
                    log.debug(errMsg, e);
                }
                // RFC 2560: responseBytes are not set on error.
                ocspResponseInformation = new OcspResponseInformation(responseGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null), OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
                transactionLogger.writeln();
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
            } catch (Throwable e) { // NOPMD, we really want to catch everything here to return internal error on unexpected errors
                transactionLogger.paramPut(IPatternLogger.PROCESS_TIME, IPatternLogger.PROCESS_TIME);
                auditLogger.paramPut(IPatternLogger.PROCESS_TIME, IPatternLogger.PROCESS_TIME);
                final String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
                log.info(errMsg);
                if (log.isDebugEnabled()) {
                    log.debug(errMsg, e);
                }
                // RFC 2560: responseBytes are not set on error.
                ocspResponseInformation = new OcspResponseInformation(responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null), OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
                transactionLogger.writeln();
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
            }
            byte[] ocspResponseBytes = ocspResponseInformation.getOcspResponse();    
            response.setContentType("application/ocsp-response");
            response.setContentLength(ocspResponseBytes.length);
            addRfc5019CacheHeaders(request, response, ocspResponseInformation);
            response.getOutputStream().write(ocspResponseBytes);
            response.getOutputStream().flush();
        } catch (Exception e) {
            log.error("", e);
            transactionLogger.flush();
            auditLogger.flush();
        }
    }

    /**
     * RFC 2560 does not specify how cache headers should be used, but RFC 5019 does. Therefore we will only
     * add the headers if the requirements of RFC 5019 is fulfilled: A GET-request, a single embedded reponse,
     * the response contains a nextUpdate and no nonce is present.
     * @param maxAge is the margin to Expire when using max-age in milliseconds 
     * @throws org.bouncycastle.cert.ocsp.OCSPException 
     */
    private void addRfc5019CacheHeaders(HttpServletRequest request, HttpServletResponse response, OcspResponseInformation ocspResponseInformation) 
                throws IOException, org.bouncycastle.cert.ocsp.OCSPException {
        if (ocspResponseInformation.getMaxAge() <= 0) {
            log.debug("Will not add RFC 5019 cache headers: RFC 5019 6.2: max-age should be 'later than thisUpdate but earlier than nextUpdate'.");
            return;
        }
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            log.debug("Will not add RFC 5019 cache headers: \"clients MUST use the GET method (to enable OCSP response caching)\"");
            return;
        }
      
        if(!ocspResponseInformation.shouldAddCacheHeaders()) {
            return;
        } 

        long now = new Date().getTime();
        long thisUpdate = ocspResponseInformation.getThisUpdate();
        long nextUpdate = ocspResponseInformation.getNextUpdate();
  
        // RFC 5019 6.2: Date: The date and time at which the OCSP server generated the HTTP response.
        // On JBoss AS the "Date"-header is cached for 1 second, so this value will be overwritten and off by up to a second 
        response.setDateHeader("Date", now);
        // RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder last modified the response. == thisUpdate
        response.setDateHeader("Last-Modified", thisUpdate);
        // RFC 5019 6.2: Expires: This date and time will be the same as the nextUpdate timestamp in the OCSP response itself.
        response.setDateHeader("Expires", nextUpdate); // This is overridden by max-age on HTTP/1.1 compatible components
        // RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII HEX representation of the SHA1 hash of the OCSPResponse structure.
        response.setHeader("ETag", "\"" + ocspResponseInformation.getResponseHeader() + "\"");
        
        OCSPResp resp = new OCSPResp(ocspResponseInformation.getOcspResponse());
        SingleResp[] singleRespones = ((BasicOCSPResp) resp.getResponseObject()).getResponses();
        if(singleRespones[0].getCertStatus() instanceof UnknownStatus) {
            // Note that using no-cache here is not conforming to RFC5019, but with more recent CABForum discussions it seems RFC5019 will not
            // be followed, or will be changed. (See ECA-3289)
            response.setHeader("Cache-Control", "no-cache, must-revalidate"); //HTTP 1.1
            response.setHeader("Pragma", "no-cache"); //HTTP 1.0 
        } else {
            // Max age is retrieved in millisecons, but it must be in seconds in the cache-control header
            long maxAge = ocspResponseInformation.getMaxAge();
            if (maxAge >= (nextUpdate - thisUpdate)) {
                maxAge = nextUpdate - thisUpdate - 1;
                log.warn(intres.getLocalizedMessage("ocsp.shrinkmaxage", maxAge));
            } 
            response.setHeader("Cache-Control", "max-age=" + (maxAge / 1000) + ",public,no-transform,must-revalidate");
        }
    }

    /**
     * Reads the request bytes and verifies min and max size of the request. If an error occurs it throws a MalformedRequestException. 
     * Can get request bytes both from a HTTP GET and POST request
     * 
     * @param request
     * @param response
     * @return the request bytes or null if an error occured.
     * @throws IOException In case there is no stream to read
     * @throws MalformedRequestException 
     */
    private byte[] checkAndGetRequestBytes(HttpServletRequest request) throws IOException, MalformedRequestException {
        final byte[] ret;
        // Get the request data
        String method = request.getMethod();
        String remoteAddress = request.getRemoteAddr();
        final int n = request.getContentLength();
        // Expect n might be -1 for HTTP GET requests
        if (log.isDebugEnabled()) {
            log.debug(">checkAndGetRequestBytes. Received " + method + " request with content length: " + n + " from " + remoteAddress);
        }
        if (n > LimitLengthASN1Reader.MAX_REQUEST_SIZE) {
            String msg = intres.getLocalizedMessage("ocsp.toolarge", LimitLengthASN1Reader.MAX_REQUEST_SIZE, n);
            log.info(msg);
            throw new MalformedRequestException(msg);
        }
        // So we passed basic tests, now we can read the bytes, but still keep an eye on the size
        // we can not fully trust the sent content length.
        if (StringUtils.equals(method, "POST")) {
            final ServletInputStream in = request.getInputStream(); // ServletInputStream does not have to be closed, container handles this
            LimitLengthASN1Reader limitLengthASN1Reader = new LimitLengthASN1Reader(in, n);
            try {
                ret = limitLengthASN1Reader.readFirstASN1Object();
                if (n > ret.length) {
                    // The client is sending more data than the OCSP request. It might be slightly broken or trying to bog down the server on purpose.
                    // In the interest of not breaking existing systems that might have slightly broken clients we just log for a warning for now.
                    String msg = intres.getLocalizedMessage("ocsp.additionaldata", ret.length, n);
                    log.warn(msg);
                }
            } finally {
                limitLengthASN1Reader.close();
            }
        } else if (StringUtils.equals(method, "GET")) {
            // GET request
            final StringBuffer url = request.getRequestURL();
            // RFC2560 A.1.1 says that request longer than 255 bytes SHOULD be sent by POST, we support GET for longer requests anyway.
            if (url.length() <= LimitLengthASN1Reader.MAX_REQUEST_SIZE) {
                final String decodedRequest;
                try {
                    // We have to extract the pathInfo manually, to avoid multiple slashes being converted to a single
                    // According to RFC 2396 2.2 chars only have to encoded if they conflict with the purpose, so
                    // we can for example expect both '/' and "%2F" in the request.
                    final String fullServletpath = request.getContextPath() + request.getServletPath();
                    final int paramIx = Math.max(url.indexOf(fullServletpath), 0) + fullServletpath.length() + 1;
                    final String requestString = paramIx < url.length() ? url.substring(paramIx) : "";
                    decodedRequest = URLDecoder.decode(requestString, "UTF-8").replaceAll(" ", "+");
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("ocsp.badurlenc");
                    log.info(msg);
                    throw new MalformedRequestException(e);
                }
                if (decodedRequest != null && decodedRequest.length() > 0) {
                    if (log.isDebugEnabled()) {
                        // Don't log the request if it's too long, we don't want to cause denial of service by filling log files or buffers.
                        if (decodedRequest.length() < 2048) {
                            log.debug("decodedRequest: " + decodedRequest);
                        } else {
                            log.debug("decodedRequest too long to log: " + decodedRequest.length());
                        }
                    }
                    try {
                        ret = Base64.decode(decodedRequest.getBytes());
                    } catch (Exception e) {
                        String msg = intres.getLocalizedMessage("ocsp.badurlenc");
                        log.info(msg);
                        throw new MalformedRequestException(e);
                    }
                } else {
                    String msg = intres.getLocalizedMessage("ocsp.missingreq");
                    log.info(msg);
                    throw new MalformedRequestException(msg);
                }
            } else {
                String msg = intres.getLocalizedMessage("ocsp.toolarge", LimitLengthASN1Reader.MAX_REQUEST_SIZE, url.length());
                log.info(msg);
                throw new MalformedRequestException(msg);
            }
        } else {
            // Strange, an unknown method
            String msg = intres.getLocalizedMessage("ocsp.unknownmethod", method);
            log.info(msg);
            throw new MalformedRequestException(msg);
        }
        // Make a final check that we actually received something
        if ((ret == null) || (ret.length == 0)) {
            String msg = intres.getLocalizedMessage("ocsp.emptyreq", remoteAddress);
            log.info(msg);
            throw new MalformedRequestException(msg);
        }
        return ret;
    }
}
