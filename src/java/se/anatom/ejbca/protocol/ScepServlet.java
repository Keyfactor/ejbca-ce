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
 
package se.anatom.ejbca.protocol;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import java.security.cert.X509Certificate;
import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.*;
import javax.servlet.http.*;

import org.apache.log4j.Logger;

import se.anatom.ejbca.apply.RequestHelper;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;


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
 * @version $Id: ScepServlet.java,v 1.28 2004-04-16 07:38:55 anatom Exp $
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
                    ICAAdminSessionHome.class );            
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
        doGet(request, response);
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

        try {
            log.debug("query string=" + request.getQueryString());

            String operation = request.getParameter("operation");
            String message = request.getParameter("message");

            if ((operation == null) || (message == null)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Parameters 'operation' and 'message' must be supplied!");
                return;
            }

            Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
            log.debug("Got request '" + operation + "'");
            log.debug("Message: " + message);

            if (operation.equals("PKIOperation")) {
                byte[] scepmsg = Base64.decode(message.getBytes());
                ISignSessionRemote signsession = signhome.create();
                ScepPkiOpHelper helper = new ScepPkiOpHelper(administrator, signsession);

                // Read the message end get the cert, this also checksauthorization
                byte[] reply = helper.scepCertRequest(scepmsg);
                if (reply == null) {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Fatal error processing Scep request");
                    return;
                }
                // Send back Scep response, PKCS#7 which contains the end entity's certificate (or failure)
                RequestHelper.sendBinaryBytes(reply, response, "application/x-pki-message");
            } else if (operation.equals("GetCACert")) {
                // The response has the content type tagged as application/x-x509-ca-cert. 
                // The body of the response is a DER encoded binary X.509 certificate. 
                // For example: "Content-Type:application/x-x509-ca-cert\n\n"<BER-encoded X509>
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                log.debug("Got SCEP cert request for CA '"+message+"'");
                Collection certs = null;
                ICAAdminSessionRemote caadminsession = caadminhome.create();          
                CAInfo cainfo = caadminsession.getCAInfo(administrator, message);
                if (cainfo != null) {
                    certs = cainfo.getCertificateChain();
                }
                if ( (certs != null) && (certs.size() > 0) ) {
                    // CAs certificate is in the first position in the Collection
                    Iterator iter = certs.iterator();
                    X509Certificate cert = (X509Certificate)iter.next();
                    log.debug("Sent certificate for CA '"+message+"' to SCEP client.");
                    RequestHelper.sendNewX509CaCert(cert.getEncoded(), response);
                } else {
                    log.error("SCEP cert request for unknown CA '"+message+"'");
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        "No CA certificates found.");
                }
            } else if (operation.equals("GetCACertChain")) {
                // The response for GetCACertChain is a certificates-only PKCS#7 
                // SignedDatato carry the certificates to the end entity, with a 
                // Content-Type of application/x-x509-ca-ra-cert-chain.
                
                // CA_IDENT is the message for this request to indicate which CA we are talking about
                log.debug("Got SCEP pkcs7 request for CA '"+message+"'");
                ICAAdminSessionRemote caadminsession = caadminhome.create();          
                CAInfo cainfo = caadminsession.getCAInfo(administrator, message);
                ISignSessionRemote signsession = signhome.create();
                byte[] pkcs7 = signsession.createPKCS7(administrator, cainfo.getCAId());
                if ( (pkcs7 != null) && (pkcs7.length > 0) ) {
                    log.debug("Sent PKCS7 for CA '"+message+"' to SCEP client.");
                    RequestHelper.sendBinaryBytes(pkcs7, response, "application/x-x509-ca-ra-cert-chain");
                } else {
                    log.error("SCEP pkcs7 request for unknown CA '"+message+"'");
                    response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        "No CA certificates found.");
                }
            } else {
                log.error("Invalid parameter '" + operation);

                // TODO: Send back proper Failure Response
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid parameter: " + operation);
            }
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

        log.debug("<doGet()");
    } // doGet

} // ScepServlet
