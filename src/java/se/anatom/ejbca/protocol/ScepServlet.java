package se.anatom.ejbca.protocol;

import java.io.*;
import java.util.Enumeration;
import java.security.Provider;
import java.security.Security;

import javax.servlet.*;
import javax.servlet.http.*;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.util.Base64;

/** Servlet implementing server side of the Simple Certificate Enrollment Protocol (SCEP)
* snip from OpenSCEP
* -----
*This processes does the following:
*
* 1. decode a PKCS#7 signed data message from the standard input
* 2. extract the signed attributes from the the message, which indicate
*     the type of request
* 3. decrypt the enveloped data PKCS#7 inside
* 4. branch to different actions depending on the type of the message:
*     - PKCSReq
*     - GetCertInitial
*     - GetCert
*     - GetCRL
*     - v2 PKCSReq or Proxy request
* 5. envelop (PKCS#7) the reply data from the previous step
* 6. sign the reply data (PKCS#7) from the previous step
* 7. output the result as a der encoded block on stdout
* -----
* @version  $Id: ScepServlet.java,v 1.10 2003-06-05 09:24:40 anatom Exp $
*/
public class ScepServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(ScepServlet.class);

    private ISignSessionHome signhome = null;
    private IUserAdminSessionHome useradminhome = null;

    public void init(ServletConfig config) throws ServletException {
    super.init(config);
        try {
            // Install BouncyCastle provider
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            // Get EJB context and home interfaces
            InitialContext ctx = new InitialContext();
            signhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
            useradminhome = (IUserAdminSessionHome) PortableRemoteObject.narrow(ctx.lookup("UserAdminSession"), IUserAdminSessionHome.class );
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(request, response);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest request,  HttpServletResponse response) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        try {
            String operation = request.getParameter("operation");
            String message = request.getParameter("message");
            if ((operation == null) || (message == null)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameters 'operation' and 'message' must be supplied!");
                return;
            }
            Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
            log.debug("Got request '" + operation + "'");
            log.debug("Message: "+message);
            if (operation.equals("PKIOperation")) {
                byte[] scepmsg = Base64.decode(message.getBytes());
                IUserAdminSessionRemote adminsession = useradminhome.create();
                ISignSessionRemote signsession = signhome.create();
                ScepPkiOpHelper helper = new ScepPkiOpHelper(administrator, adminsession, signsession);
                // We are not ready yet, so lets deny all requests for now...
                // TODO:
                response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Not implemented");
                
                if (false) helper.scepCertRequest(scepmsg);                    
            } else if (operation.equals("GetCACert")) {
                // TODO:
                response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Not implemented");
            } else if (operation.equals("GetCACertChain")) {
                // TODO:
                response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Not implemented");
            } else {
                log.error("Invalid parameter '"+operation);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameter: "+operation);
            }
        } catch (java.lang.ArrayIndexOutOfBoundsException ae) {
            log.error("Empty or invalid request received.", ae);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, ae.getMessage());
        } catch (AuthorizationDeniedException ae) {
            log.error("Authorization denied.", ae);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthLoginException ae) {
            log.error("Authorization denied.", ae);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (AuthStatusException ae) {
            log.error("Wrong client status.", ae);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ae.getMessage());
        } catch (Exception e) {
            log.error("Error in ScepServlet:", e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
        log.debug("<doGet()");
    } // doGet

    /**
     * Prints debug info back to browser client
     **/
    private class Debug {
        final private ByteArrayOutputStream buffer;
        final private PrintStream printer;
        final private HttpServletRequest request;
        final private HttpServletResponse response;
        Debug(HttpServletRequest request, HttpServletResponse response){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);
            this.request=request;
            this.response=response;
        }

        void printDebugInfo() throws IOException, ServletException {
            request.setAttribute("ErrorMessage",new String(buffer.toByteArray()));
            request.getRequestDispatcher("/error.jsp").forward(request, response);
        }

        void print(Object o) {
            printer.println(o);
        }
        void printMessage(String msg) {
            print("<p>"+msg);
        }
        void printInsertLineBreaks( byte[] bA ) throws Exception {
            BufferedReader br=new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(bA)) );
            while ( true ){
                String line=br.readLine();
                if (line==null)
                    break;
                print(line.toString()+"<br>");
            }
        }
        void takeCareOfException(Throwable t ) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            t.printStackTrace(new PrintStream(baos));
            print("<h4>Exception:</h4>");
            try {
                printInsertLineBreaks( baos.toByteArray() );
            } catch (Exception e) {
                e.printStackTrace(printer);
            }
            request.setAttribute("Exception", "true");
        }
    } // Debug

} // ScepServlet
