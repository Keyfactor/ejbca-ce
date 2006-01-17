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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.pub.RequestHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;


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
 * @version $Id: ScepServlet.java,v 1.1 2006-01-17 20:32:20 anatom Exp $
 */
public class ScepServlet extends HttpServlet {
    private static Logger log = Logger.getLogger(ScepServlet.class);
    private ISignSessionHome signhome = null;
    private ICAAdminSessionHome caadminhome = null;

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
            CertTools.installBCProvider();

            // Get EJB context and home interfaces
            InitialContext ctx = new InitialContext();
            signhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"),
                    ISignSessionHome.class);
            caadminhome = (ICAAdminSessionHome) PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"),
                    ICAAdminSessionHome.class);
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
        log.debug(">doPost()");
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
        log.debug("<doPost()");
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
        log.debug(">doGet()");

            log.debug("query string=" + request.getQueryString());

            // These are mandatory in SCEP GET
            /*
             GET /cgi-bin/pkiclient.exe?operation=PKIOperation&message=MIAGCSqGSIb3D
             QEHA6CAMIACAQAxgDCBzAIBADB2MGIxETAPBgNVBAcTCE ......AAAAAA== 
             */
            String operation = request.getParameter("operation");
            String message = request.getParameter("message");

            service(operation, message, request.getRemoteAddr(), response);
            
        log.debug("<doGet()");
    } // doGet

    private void service(String operation, String message, String remoteAddr, HttpServletResponse response) throws IOException {
        try {
            if ((operation == null) || (message == null)) {
                log.error("Got request missing operation and/or message parameters.");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                "Parameters 'operation' and 'message' must be supplied!");
                return;
            }
            
            Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);
            log.debug("Got request '" + operation + "'");
            log.debug("Message: " + message);
            
            if (operation.equals("PKIOperation")) {
                byte[] scepmsg = Base64.decode(message.getBytes());
                ISignSessionRemote signsession = signhome.create();
                ScepPkiOpHelper helper = new ScepPkiOpHelper(administrator, signsession);
                
                // Read the message end get the cert, this also checksauthorization
                boolean includeCACert = true;
                if (StringUtils.equals("0", getInitParameter("includeCACert"))) {
                	includeCACert = false;
                }
                byte[] reply = helper.scepCertRequest(scepmsg, includeCACert);
                if (reply == null) {
                    // This is probably a getCert message?
                    response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                    "Can not handle request");
                    return;
                }
                // Send back Scep response, PKCS#7 which contains the end entity's certificate (or failure)
                RequestHelper.sendBinaryBytes(reply, response, "application/x-pki-message");
            } else if (operation.equals("GetCACert")) {
                // The response has the content type tagged as application/x-x509-ca-cert. 
                // The body of the response is a DER encoded binary X.509 certificate. 
                // For example: "Content-Type:application/x-x509-ca-cert\n\n"<BER-encoded X509>
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                log.debug("Got SCEP cert request for CA '" + message + "'");
                Collection certs = null;
                ICAAdminSessionRemote caadminsession = caadminhome.create();
                CAInfo cainfo = caadminsession.getCAInfo(administrator, message);
                if (cainfo != null) {
                    certs = cainfo.getCertificateChain();
                }
                if ((certs != null) && (certs.size() > 0)) {
                    // CAs certificate is in the first position in the Collection
                    Iterator iter = certs.iterator();
                    X509Certificate cert = (X509Certificate) iter.next();
                    log.debug("Sent certificate for CA '" + message + "' to SCEP client.");
                    RequestHelper.sendNewX509CaCert(cert.getEncoded(), response);
                } else {
                    log.error("SCEP cert request for unknown CA '" + message + "'");
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "No CA certificates found.");
                }
            } else if (operation.equals("GetCACertChain")) {
                // The response for GetCACertChain is a certificates-only PKCS#7 
                // SignedDatato carry the certificates to the end entity, with a 
                // Content-Type of application/x-x509-ca-ra-cert-chain.
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                log.debug("Got SCEP pkcs7 request for CA '" + message + "'");
                ICAAdminSessionRemote caadminsession = caadminhome.create();
                CAInfo cainfo = caadminsession.getCAInfo(administrator, message);
                ISignSessionRemote signsession = signhome.create();
                byte[] pkcs7 = signsession.createPKCS7(administrator, cainfo.getCAId(), true);
                if ((pkcs7 != null) && (pkcs7.length > 0)) {
                    log.debug("Sent PKCS7 for CA '" + message + "' to SCEP client.");
                    RequestHelper.sendBinaryBytes(pkcs7, response, "application/x-x509-ca-ra-cert-chain");
                } else {
                    log.error("SCEP pkcs7 request for unknown CA '" + message + "'");
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "No CA certificates found.");
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
                
                // TODO: Send back proper Failure Response
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid parameter: " + operation);
            }
        } catch (CADoesntExistsException cae) {
            log.error("SCEP cert request for unknown CA, or can't find user.", cae);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_NOT_FOUND, cae.getMessage());
        } catch (java.lang.ArrayIndexOutOfBoundsException ae) {
            log.error("Empty or invalid request received.", ae);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, ae.getMessage());
        } catch (AuthorizationDeniedException ae) {
            log.error("Authorization denied.", ae);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthLoginException ae) {
            log.error("Authorization denied.", ae);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthStatusException ae) {
            log.error("Wrong client status.", ae);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (Exception e) {
            log.error("Error in ScepServlet:", e);
            
            // TODO: Send back proper Failure Response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }
    
} // ScepServlet
