package se.anatom.ejbca.protocol;

import java.io.*;

import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
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
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.util.Base64;


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
 * @version $Id: ScepServlet.java,v 1.22 2003-10-09 08:46:27 anatom Exp $
 */
public class ScepServlet extends HttpServlet {
    private static Logger log = Logger.getLogger(ScepServlet.class);
    private ISignSessionHome signhome = null;

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
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            // Get EJB context and home interfaces
            InitialContext ctx = new InitialContext();
            signhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"),
                    ISignSessionHome.class);
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
                // TODO: check CA_IDENT for this request if we have more than one CA
                // Send back DER-encoded CA cert with content-type 'application/x-x509-ca-cert'
                ISignSessionRemote signsession = signhome.create();
                Certificate[] certs = null;
                // TODO:
                // certs = signsession.getCertificateChain(administrator);

                if (certs.length == 0) {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Error getting CA certificate");
                }

                RequestHelper.sendNewX509CaCert(certs[0].getEncoded(), response);
            } else if (operation.equals("GetCACertChain")) {
                // TODO: check CA_IDENT for this request if we have more than one CA
                // Send back DER-encoded CA cert with content-type 'application/x-x509-ca-cert'
                ISignSessionRemote signsession = signhome.create();

                // Create pkcs7 with chain and send bach with content-type 'application/x-x509-ca-ra-cert-chain'
                byte[] pkcs7 = signsession.createPKCS7(administrator, 0);

                if (pkcs7.length == 0) {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Error getting CA certificate chain");
                }

                RequestHelper.sendBinaryBytes(pkcs7, response, "application/x-x509-ca-ra-cert-chain");
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
