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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
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
 * 5. envelop (PKCS#7) the reply data from the previous step 
 * 6. sign the reply data (PKCS#7) from the previous step 
 * 7. output the result as a der encoded block on stdout 
 * -----
 *
 * @version $Id$
 */
public class ScepServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(ScepServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private SignSessionLocal signsession;
    @EJB
    private CaSessionLocal casession;

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
        log.trace(">doPost()");
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
        service(operation, message, request.getRemoteAddr(), response);
        log.trace("<doPost()");
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
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException, ServletException {
        log.trace(">doGet()");

            log.debug("query string=" + request.getQueryString());

            // These are mandatory in SCEP GET
            /*
             GET /cgi-bin/pkiclient.exe?operation=PKIOperation&message=MIAGCSqGSIb3D
             QEHA6CAMIACAQAxgDCBzAIBADB2MGIxETAPBgNVBAcTCE ......AAAAAA== 
             */
            String operation = request.getParameter("operation");
            String message = request.getParameter("message");
        	// Some clients don't url encode the + sign in the request for Base64 data
            if (message != null && operation != null && operation.equals("PKIOperation")) {
            	message = message.replace(' ', '+');
            }

            service(operation, message, request.getRemoteAddr(), response);
            
        log.trace("<doGet()");
    } // doGet

    private void service(String operation, String message, String remoteAddr, HttpServletResponse response) throws IOException {
        try {
            if ((operation == null) || (message == null)) {
        		String errMsg = intres.getLocalizedMessage("scep.errormissingparam", remoteAddr);
                log.error(errMsg);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,errMsg);
                return;
            }
            
			final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScepServlet: "+remoteAddr));
            //Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);
            log.debug("Got request '" + operation + "'");
            log.debug("Message: " + message);
    		String iMsg = intres.getLocalizedMessage("scep.receivedmsg", remoteAddr);
			log.info(iMsg);
            if (operation.equals("PKIOperation")) {
                byte[] scepmsg = Base64.decode(message.getBytes());
                ScepPkiOpHelper helper = new ScepPkiOpHelper(administrator, signsession);
                
                // Read the message end get the cert, this also checksauthorization
                boolean includeCACert = true;
                if (StringUtils.equals("0", getInitParameter("includeCACert"))) {
                	includeCACert = false;
                }
                byte[] reply = helper.scepCertRequest(scepmsg, includeCACert);
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
                log.debug("Got SCEP cert request for CA '" + message + "'");
                Collection<Certificate> certs = null;
                CAInfo cainfo = casession.getCAInfo(administrator, message);
                if (cainfo != null) {
                    certs = cainfo.getCertificateChain();
                }
                if ((certs != null) && (certs.size() > 0)) {
                    // CAs certificate is in the first position in the Collection
                    Iterator<Certificate> iter = certs.iterator();
                    X509Certificate cert = (X509Certificate) iter.next();
                    log.debug("Sent certificate for CA '" + message + "' to SCEP client.");
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
                log.debug("Got SCEP pkcs7 request for CA '" + message + "'");
  
                CAInfo cainfo = casession.getCAInfo(administrator, message);
                byte[] pkcs7 = signsession.createPKCS7(administrator, cainfo.getCAId(), true);
                if ((pkcs7 != null) && (pkcs7.length > 0)) {
                    log.debug("Sent PKCS7 for CA '" + message + "' to SCEP client.");
                    RequestHelper.sendBinaryBytes(pkcs7, response, "application/x-x509-ca-ra-cert-chain", null);
            		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetCACertChain", remoteAddr);
        			log.info(iMsg);
                } else {
            		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "pkcs7");
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,"No CA certificates found.");
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
                log.debug("Got SCEP CACaps request for CA '" + message + "'");
                response.setContentType("text/plain");
                response.getOutputStream().print("POSTPKIOperation\nSHA-1");
            } else {
                log.error("Invalid parameter '" + operation);
                // Send back proper Failure Response
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameter: " + HTMLTools.htmlescape(operation));
            }
        } catch (CADoesntExistsException cae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
            log.error(errMsg, cae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_NOT_FOUND, cae.getMessage());
        } catch (java.lang.ArrayIndexOutOfBoundsException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorinvalidreq");
            log.error(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, ae.getMessage());
        } catch (AuthorizationDeniedException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorauth");
            log.error(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthLoginException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorauth");
            log.error(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthStatusException ae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorclientstatus");
            log.error(errMsg, ae);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (CryptoTokenOfflineException ee) {
    		String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            log.error(errMsg, ee);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ee.getMessage());
        } catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            log.error(errMsg, e);
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }
    
} // ScepServlet
