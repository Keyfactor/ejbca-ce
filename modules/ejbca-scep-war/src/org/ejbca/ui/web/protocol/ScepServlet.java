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
import java.security.SignatureException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.NoSuchAliasException;
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
    /** Only intended to check if Peer connected instance is authorized to SCEP at all. This will not affect user authorization */
    private final AuthenticationToken raScepAuthCheckToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("scepProtocolAuthCheck"));
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    
    private static final String DEFAULT_SCEP_ALIAS = "scep";

    /**
     * Inits the SCEP servlet
     *
     * @param config servlet configuration
     *
     * @throws ServletException on error during initialization
     */
    @Override
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
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        log.trace(">SCEP doPost()");
        final boolean isProtocolAuthorized = raMasterApiProxyBean.isAuthorizedNoLogging(raScepAuthCheckToken,
                AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP);
        if (!isProtocolAuthorized) {
            log.info("SCEP Protocol not authorized for this Peer");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "SCEP Protocol not authorized for this Peer");
            return;
        }
        
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
    }

    /**
     * Handles HTTP get
     *
     * @param request java standard arg
     * @param response java standard arg
     *
     * @throws IOException input/output error
     * @throws ServletException if the post could not be handled
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        log.trace(">SCEP doGet()");
        if (log.isDebugEnabled()) {
            log.debug("query string=" + request.getQueryString());
        }
        final boolean isProtocolAuthorized = raMasterApiProxyBean.isAuthorizedNoLogging(raScepAuthCheckToken,
                AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP);
        if (!isProtocolAuthorized) {
            log.info("SCEP Protocol not authorized for this Peer");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "SCEP Protocol not authorized for this Peer");
            return;
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
    }

    private void service(final String operation, final String message, final String remoteAddr, final HttpServletResponse response,
            final String pathInfo) throws IOException {
        final String alias = getAlias(pathInfo);
        if(alias == null) {
            log.info("Wrong URL format. The SCEP URL should look like: " +
            		"'http://HOST:PORT/ejbca/publicweb/apply/scep/ALIAS/pkiclient.exe' " +
            		"but was 'http://HOST:PORT/ejbca/publicweb/apply/scep" + pathInfo + "'");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Wrong URL. No alias found.");
            return;
        }
        if(alias.length() > 32) {
            log.info("Unaccepted alias more than 32 characters.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unaccepted alias more than 32 characters.");
            return;
        }
        
        try {
            if (operation == null) {
        		String errMsg = intres.getLocalizedMessage("scep.errormissingparam", remoteAddr);
                log.error(errMsg);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,errMsg);
                return;
            }
            if (operation.equals("PKIOperation") && message == null) {
                if (message == null) {
                    String errMsg = intres.getLocalizedMessage("scep.errormissingparam", remoteAddr);
                    log.error(errMsg);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST,errMsg);
                    return;
                }
            }
            final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal("ScepServlet", remoteAddr));
            if (log.isDebugEnabled()) {
                log.debug("Got request '" + operation + "'");
                log.debug("Message: " + message);
            }
    		String iMsg = intres.getLocalizedMessage("scep.receivedmsg", remoteAddr);
			log.info(iMsg);	
			byte[] dispatchResponse = raMasterApiProxyBean.scepDispatch(administrator, operation, message, alias);
			
            if (operation.equals("PKIOperation")) {
                if (dispatchResponse == null) {
                    response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Can not handle request");
                    return;
                }
                // Send back Scep response, PKCS#7 which contains the end entity's certificate (or failure)
                RequestHelper.sendBinaryBytes(dispatchResponse, response, "application/x-pki-message", null);
        		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "PKIOperation", remoteAddr);
    			log.info(iMsg);
            } else if (operation.equals("GetCACert")) {
                // The response has the content type tagged as application/x-x509-ca-cert. 
                // The body of the response is a DER encoded binary X.509 certificate. 
                // For example: "Content-Type:application/x-x509-ca-cert\n\n"<BER-encoded X509>
                if (dispatchResponse != null) {
                    log.debug("Sent CA certificate to SCEP client.");
                    RequestHelper.sendNewX509CaCert(dispatchResponse, response);
            		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetCACert", remoteAddr);
        			log.info(iMsg);
                } else {
                    String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "GetCACert", message);
                    log.info(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "No CA certificates found.");
                }
            } else if (operation.equals("GetCACertChain")) {
                // GetCACertChain was included in SCEP draft 18, "5.6.  Get Certificate Authority Certificate Chain"
                // This dissapeared on SCEP draft 19 however, so we should not expect any clients to use this method.
                
                // The response for GetCACertChain is a certificates-only PKCS#7 
                // SignedData to carry the certificates to the end entity, with a 
                // Content-Type of application/x-x509-ca-ra-cert-chain.
                if (dispatchResponse != null) {
                    log.debug("Sent PKCS7 for CA to SCEP client.");
                    RequestHelper.sendBinaryBytes(dispatchResponse, response, "application/x-x509-ca-ra-cert-chain", null);
            		iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetCACertChain", remoteAddr);
        			log.info(iMsg);
                } else {
            		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "GetCACertChain", message);
                    log.info(errMsg);
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "No CA certificates found.");
                }
            } else if (operation.equals("GetNextCACert")) {
                // Like GetCACert, but returns the next certificate during certificate rollover
                if (dispatchResponse != null) {
                    RequestHelper.sendBinaryBytes(dispatchResponse, response, "application/x-x509-next-ca-cert", null);
                    iMsg = intres.getLocalizedMessage("scep.sentresponsemsg", "GetNextCACert", remoteAddr);
                    log.info(iMsg);
                } else {
                    String errMsg = intres.getLocalizedMessage("scep.errornorollovercert", message);
                    log.info(errMsg);
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "No rollover certificate found for this CA.");
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
                response.getOutputStream().print(new String(dispatchResponse));
            } else {
                log.error("Invalid parameter '" + operation);
                // Send back proper Failure Response
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameter: " + HTMLTools.htmlescape(operation));
            }
        } catch (CADoesntExistsException cae) {
    		String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "cert");
            log.info(errMsg+": "+cae.getMessage());
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
            if (log.isDebugEnabled()) {
                // AuthLogin is logged as a security event already by inner layers, not need to log the exception at info level
                // this is seens clearly in the info log already, more details is inly needed in debug level
                final String errMsg = intres.getLocalizedMessage("scep.errorauth");
                log.debug(errMsg, ae);
            }
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
        } catch(CertificateRenewalException e) {
            String errMsg = intres.getLocalizedMessage("scep.errorclientcertificaterenewal");
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch (NoSuchAliasException e) {
            String msg = intres.getLocalizedMessage("protocol.nosuchalias", "SCEP", alias);
            log.info(msg);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
        } catch (Exception e) {             
    		String errMsg = intres.getLocalizedMessage("scep.errorgeneral");
            log.info(errMsg, e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
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

}
