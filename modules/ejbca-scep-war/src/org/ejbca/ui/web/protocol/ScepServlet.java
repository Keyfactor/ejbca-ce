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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.core.protocol.scep.ScepResponseMessage;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;


/**
 * Servlet implementing server side of the Simple Certificate Enrollment Protocol (SCEP) 
 * ----- 
 * This processes does the following: 
 * 1. decode a PKCS#7 signed data message from the standard input 
 * 2. extract the signed attributes from the the message, which indicate the type of request 
 * 3. decrypt the enveloped data PKCS#7 inside 
 * 4. branch to different actions depending on the type of the message: 
 * - PKCSReq 
 * - GetCertInitial 
 * - GetCert 
 * - GetCRL 
 * - v2PKCSReq or Proxy request 
 * - GetCACaps
 * 5. envelop (PKCS#7) the reply data from the previous step 
 * 6. sign the reply data (PKCS#7) from the previous step 
 * 7. output the result as a der encoded block on stdout 
 * -----
 *
 * @version $Id$
 */
public class ScepServlet extends HttpServlet {
    private static final long serialVersionUID = -6776853218419335240L;
    private static final Logger log = Logger.getLogger(ScepServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String SCEP_RA_MODE_EXTENSION_CLASSNAME = "org.ejbca.ui.web.protocol.ScepRaModeExtension";
    public static final String SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME = "org.ejbca.ui.web.protocol.ClientCertificateRenewalExtension";   
    
    @EJB
    private CaSessionLocal casession;
    @EJB
    private CertificateProfileSessionLocal certProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;   
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;
    @EJB
    private SignSessionLocal signsession;

    
    private static final String DEFAULT_SCEP_ALIAS = "scep";

    private transient ScepOperationPlugin scepRaModeExtension = null;
    private transient ScepResponsePlugin scepClientCertificateRenewal = null;

    @PostConstruct
    public void postConstruct() {
        try {
            @SuppressWarnings("unchecked")
            Class<? extends ScepOperationPlugin> extensionClass = (Class<? extends ScepOperationPlugin>) Class.forName(SCEP_RA_MODE_EXTENSION_CLASSNAME);
            scepRaModeExtension = extensionClass.newInstance();
        } catch (ClassNotFoundException e) {
            scepRaModeExtension = null;
        } catch (InstantiationException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } catch (IllegalAccessException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        }
        
        try {
            @SuppressWarnings("unchecked")
            Class<ScepResponsePlugin> extensionClass = (Class<ScepResponsePlugin>) Class.forName(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME);
            scepClientCertificateRenewal = extensionClass.newInstance();
        } catch (ClassNotFoundException e) {
            scepClientCertificateRenewal = null;
        } catch (InstantiationException e) {
            scepClientCertificateRenewal = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } catch (IllegalAccessException e) {
            scepClientCertificateRenewal = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        }
    }
    
    
    /**
     * Inits the SCEP servlet
     *
     * @param config servlet configuration
     *
     * @throws ServletException on error during initialization
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            // Install BouncyCastle provider
            CryptoProviderTools.installBCProviderIfNotAvailable();
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    /**
     * Handles HTTP post
     *
     * @param request java standard arg
     * @param response java standard arg
     *
     * @throws IOException input/output error
     * @throws ServletException if the post could not be handled
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        log.trace(">SCEP doPost()");
        /* 
         If the remote CA supports it, any of the PKCS#7-encoded SCEP messages
         may be sent via HTTP POST instead of HTTP GET.   This is allowed for
         any SCEP message except GetCACert, GetCACertChain, GetNextCACert,
         or GetCACaps.  In this form of the message, Base 64 encoding is not
         used.
         
         POST /cgi-bin/pkiclient.exe?operation=PKIOperation
         <binary PKCS7 data>
         */
        String operation = "PKIOperation";
        ServletInputStream sin = request.getInputStream();
        // This small code snippet is inspired/copied by apache IO utils to Tomas Gustavsson...
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n = 0;
        while (-1 != (n = sin.read(buf))) {
            output.write(buf, 0, n);
        }
        String message = new String(Base64.encode(output.toByteArray()));
        service(operation, message, request.getRemoteAddr(), response, request.getPathInfo());
        log.trace("<SCEP doPost()");
    } //doPost

    /**
     * Handles HTTP get
     *
     * @param request java standard arg
     * @param response java standard arg
     *
     * @throws IOException input/output error
     * @throws ServletException if the post could not be handled
     */
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        log.trace(">SCEP doGet()");
        if (log.isDebugEnabled()) {
            log.debug("query string=" + request.getQueryString());
        }

        // These are mandatory in SCEP GET
        /*
         GET /cgi-bin/pkiclient.exe?operation=PKIOperation&message=MIAGCSqGSIb3D
         QEHA6CAMIACAQAxgDCBzAIBADB2MGIxETAPBgNVBAcTCE ......AAAAAA== 
         */
        String operation = request.getParameter("operation");
        String message = request.getParameter("message");
        // Some clients don't url encode the + sign in the request. Message is only used to PKIOperations
        if (message != null && operation != null && operation.equals("PKIOperation")) {
            message = message.replace(' ', '+');
        }

        service(operation, message, request.getRemoteAddr(), response, request.getPathInfo());

        log.trace("<SCEP doGet()");
    } // doGet

    private void service(String operation, String message, String remoteAddr, HttpServletResponse response, String pathInfo) throws IOException {

        String alias = getAlias(pathInfo);
        if(alias == null) {
            log.info("Wrong URL format. The SCEP URL should look like: " +
            		"'http://HOST:PORT/ejbca/publicweb/apply/scep/ALIAS/pkiclien.exe' " +
            		"but was 'http://HOST:PORT/ejbca/publicweb/apply/scep" + pathInfo + "'");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Wrong URL. No alias found.");
            return;
        }
        if(alias.length() > 32) {
            log.info("Unaccepted alias more than 32 characters.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unaccepted alias more than 32 characters.");
            return;
        }
        ScepConfiguration scepConfig = (ScepConfiguration) this.globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        if(!scepConfig.aliasExists(alias)) {
            String msg = "SCEP alias '" + alias + "' does not exist";
            log.info(msg);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
            return;
        }
        
        try {
            if (operation == null) {
        		String errMsg = intres.getLocalizedMessage("scep.errormissingparam", remoteAddr);
                log.error(errMsg);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,errMsg);
                return;
            }
            
			final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScepServlet: "+remoteAddr));
            if (log.isDebugEnabled()) {
                log.debug("Got request '" + operation + "'");
                log.debug("Message: " + message);
            }
    		String iMsg = intres.getLocalizedMessage("scep.receivedmsg", remoteAddr);
			log.info(iMsg);
            if (operation.equals("PKIOperation")) {
                if (message == null) {
                    String errMsg = intres.getLocalizedMessage("scep.errormissingparam", remoteAddr);
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST,errMsg);
                    return;
                }
                
                byte[] scepmsg = Base64.decode(message.getBytes());
                                
                // Read the message end get the cert, this also checks authorization
                byte[] reply = scepCertRequest(administrator, scepmsg, alias, scepConfig);
                if (reply == null) {
                    // This is probably a getCert message?
                    response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Can not handle request");
                    return;
                }
                // Send back Scep response, PKCS#7 which contains the end entity's certificate (or failure)
                RequestHelper.sendBinaryBytes(reply, response, "application/x-pki-message", null);
        		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "PKIOperation", remoteAddr);
    			log.info(iMsg);
            } else if (operation.equals("GetCACert")) {
                // The response has the content type tagged as application/x-x509-ca-cert. 
                // The body of the response is a DER encoded binary X.509 certificate. 
                // For example: "Content-Type:application/x-x509-ca-cert\n\n"<BER-encoded X509>
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                final String caname = getCAName(message);
                if (log.isDebugEnabled()) {
                    log.debug("Got SCEP cert request for CA '" + caname + "'");
                }
                Collection<Certificate> certs = null;
                CAInfo cainfo = casession.getCAInfoInternal(-1, caname, true);
                if (cainfo != null) {
                    certs = cainfo.getCertificateChain();
                }
                if ((certs != null) && (certs.size() > 0)) {
                    // CAs certificate is in the first position in the Collection
                    X509Certificate cert = (X509Certificate) certs.iterator().next();
                    if (log.isDebugEnabled()) {
                        log.debug("Sent certificate for CA '" + caname + "' to SCEP client.");
                    }
                    RequestHelper.sendNewX509CaCert(cert.getEncoded(), response);
            		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetCACert", remoteAddr);
        			log.info(iMsg);
                } else {
            		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "No CA certificates found.");
                }
            } else if (operation.equals("GetCACertChain")) {
                // The response for GetCACertChain is a certificates-only PKCS#7 
                // SignedDatato carry the certificates to the end entity, with a 
                // Content-Type of application/x-x509-ca-ra-cert-chain.
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                final String caname = getCAName(message);
                log.debug("Got SCEP pkcs7 request for CA '" + caname + "'");
  
                CAInfo cainfo = casession.getCAInfo(administrator, caname);
                byte[] pkcs7 = signsession.createPKCS7(administrator, cainfo.getCAId(), true);
                if ((pkcs7 != null) && (pkcs7.length > 0)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Sent PKCS7 for CA '" + caname + "' to SCEP client.");
                    }
                    RequestHelper.sendBinaryBytes(pkcs7, response, "application/x-x509-ca-ra-cert-chain", null);
            		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetCACertChain", remoteAddr);
        			log.info(iMsg);
                } else {
            		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "pkcs7");
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,"No CA certificates found.");
                }
            } else if (operation.equals("GetNextCACert")) {
                // Like GetCACert, but returns the next certificate during certificate rollover
                final String caname = getCAName(message);
                if (log.isDebugEnabled()) {
                    log.debug("Got SCEP next cert request for CA '" + caname + "'");
                }
                Certificate nextcert = null;
                final CAInfo cainfo = casession.getCAInfoInternal(-1, caname, true);
                if (cainfo == null) {
                    String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "No such CA.");
                } else {
                    nextcert = casession.getFutureRolloverCertificate(cainfo.getCAId());
                    if (nextcert != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Sent next certificate for CA '" + caname + "' to SCEP client.");
                        }
                        final byte[] bytes = signsession.createPKCS7Rollover(administrator, cainfo.getCAId());
                        RequestHelper.sendBinaryBytes(bytes, response, "application/x-x509-next-ca-cert", null);
                        iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetNextCACert", remoteAddr);
                        log.info(iMsg);
                    } else {
                        String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
                        log.error(errMsg);
                        response.sendError(HttpServletResponse.SC_NOT_FOUND, "No rollover certificates found for CA.");
                    }
                }
            } else if (operation.equals("GetCACaps")) {
                // The response for GetCACaps is a <lf> separated list of capabilities

                /*
                 "GetNextCACert"       CA Supports the GetNextCACert message.
                 "POSTPKIOperation"    PKIOPeration messages may be sent via HTTP POST.
                 "SHA-1"               CA Supports the SHA-1 hashing algorithm in 
                                       signatures and fingerprints.  If present, the
                                       client SHOULD use SHA-1.  If absent, the client
                                       MUST use MD5 to maintain backward compatability.
                 "Renewal"             Clients may use current certificate and key to
                                       authenticate an enrollment request for a new
                                       certificate.  
                 */
                log.debug("Got SCEP GetCACaps request");
                response.setContentType("text/plain");
                response.getOutputStream().print("POSTPKIOperation\nGetNextCACert\nRenewal\nSHA-1");
            } else {
                log.error("Invalid parameter '" + operation);
                // Send back proper Failure Response
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameter: " + HTMLTools.htmlescape(operation));
            }
        } catch (CADoesntExistsException cae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
            log.info(errMsg, cae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_NOT_FOUND, cae.getMessage());
        } catch (DecoderException de) {
    		String errMsg = intres.getLocalizedMessage("scep.errorinvalidreq");
            log.info(errMsg, de);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, de.getMessage());
        } catch (AuthorizationDeniedException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorauth");
            log.info(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthLoginException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorauth");
            log.info(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthStatusException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorclientstatus");
            log.info(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (CryptoTokenOfflineException ee) {
    		String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            log.info(errMsg, ee);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ee.getMessage());
        } catch (NoSuchEndEntityException ee) {
            String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            errMsg += " Registering new EndEntities is only allowed in RA mode.";
            log.info(errMsg, ee);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, ee.getMessage());    
        } catch(IllegalKeyException e) {
            String errMsg = intres.getLocalizedMessage("scep.errorclientcertificaterenewal");
            errMsg += " Reusing the old keys was attempted, but this action is prohibited by configuration.";
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());    
        } catch(SignatureException e) {
            String errMsg = intres.getLocalizedMessage("scep.errorclientcertificaterenewal");
            errMsg += " Request was not signed with previous certificate's public key.";
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch(ClientCertificateRenewalException e) {
            String errMsg = intres.getLocalizedMessage("scep.errorclientcertificaterenewal");
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch (Exception e) {             
    		String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }
    
    /** Later SCEP draft say that for GetCACert message is optional. If message is there, it is the CA name
     * but if message is not provided by the client, some default CA should be used.
     * @param message the message part for the SCEP get request, can be null or empty string
     * @return the message parameter or the default CA from ALIAS.defaultca property if message is null or empty.
     */
    private String getCAName(final String message) {
        // If message is a string, return it, but if message is empty return default CA
        if (StringUtils.isEmpty(message)) {
            return EjbcaConfiguration.getScepDefaultCA();
        }
        return message;
    }
    
    public static String getAlias(String pathInfo) {
        // PathInfo contains the alias used for SCEP configuration. 
        // The SCEP URL for custom configuration looks like: http://HOST:PORT/ejbca/publicweb/apply/scep/*
        // pathInfo contains what * is and should have the form "/<SOME IDENTIFYING TEXT>/pkiclient.exe". We extract the "SOME IDENTIFYING 
        // TEXT" and that will be the SCEP configuration alias.
        
        String alias = null;
        Pattern pattern = Pattern.compile("/?([A-Za-z0-9]*)/pkiclient.exe");
        Matcher matcher = pattern.matcher(pathInfo);
        
        if(matcher.find()) {
            alias = matcher.group(1);
            if(alias.length() == 0) {
                log.info("No SCEP alias specified in the URL. Using the default alias: " + DEFAULT_SCEP_ALIAS);
                alias = DEFAULT_SCEP_ALIAS;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Found SCEP configuration alias: " + alias);
                }
            }
        }
        return alias;
    }
    
    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     * @param alias the alias of the SCEP configuration
     * @param scepConfig The SCEP configuration
     *
     * @return byte[] containing response to be sent to client.
     * @throws AuthorizationDeniedException 
     * @throws CertificateExtensionException if msg specified invalid extensions
     * @throws InvalidAlgorithmException 
     * @throws CAOfflineException 
     * @throws IllegalValidityException 
     * @throws CertificateSerialNumberException 
     * @throws CertificateRevokeException 
     * @throws CertificateCreateException 
     * @throws IllegalNameException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws CADoesntExistsException 
     * @throws IllegalKeyException 
     * @throws CryptoTokenOfflineException 
     * @throws CustomCertificateSerialNumberException 
     * @throws ClientCertificateRenewalException if an error occurs during Client Certificate Renewal
     * @throws SignatureException if a Client Certificate Renewal request was badly signed. 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws CertificateException 
     * @throws InvalidKeyException 
     * @throws {@link NoSuchEndEntityException} if end entity wasn't found, and RA mode isn't available. 
     */
    private byte[] scepCertRequest(AuthenticationToken administrator, byte[] msg, final String alias, final ScepConfiguration scepConfig)
            throws AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            ClientCertificateRenewalException, SignatureException, InvalidKeyException, CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
      byte[] ret = null;
        if (log.isTraceEnabled()) {
            log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }
        
        try {
            boolean includeCACert = scepConfig.getIncludeCA(alias);
            final ScepRequestMessage reqmsg = new ScepRequestMessage(msg, includeCACert);        
            boolean isRAModeOK = scepConfig.getRAMode(alias);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
                if (isRAModeOK && scepRaModeExtension == null) {
                    //Fail nicely
                    log.warn("SCEP RA mode is enabled, but not included in the community version of EJBCA. Unable to continue.");
                    return null;
                } else if (isRAModeOK) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP is operating in RA mode: " + isRAModeOK);
                    }
                    if (!scepRaModeExtension.performOperation(administrator, reqmsg, scepConfig, alias)) {
                        String errmsg = "Error. Failed to add or edit user: " + reqmsg.getUsername();
                        log.error(errmsg);
                        return null;
                    }
                }
                if (scepClientCertificateRenewal != null && scepConfig.getClientCertificateRenewal(alias)) {
                    ResponseMessage resp = scepClientCertificateRenewal.performOperation(administrator, reqmsg, scepConfig, alias);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                    }
                } else {                
                    // Get the certificate 
                    ResponseMessage resp = signsession.createCertificate(administrator, reqmsg, ScepResponseMessage.class, null);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                    }
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs private key is needed to decrypt
                ResponseMessage resp = signsession.getCRL(administrator, reqmsg, ScepResponseMessage.class);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } 
        if (log.isTraceEnabled()) {
            log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }
        return ret;
    }
    
    
} // ScepServlet
