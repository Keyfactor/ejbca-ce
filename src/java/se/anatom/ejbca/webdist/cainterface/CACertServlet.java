
package se.anatom.ejbca.webdist.cainterface;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Date;
import java.util.Properties;
import java.security.cert.*;
import java.math.BigInteger;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import se.anatom.ejbca.util.Base64;

import org.apache.log4j.*;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.util.CertTools;

import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.GlobalConfiguration;
/**
 * Servlet used to distribute ca certificates <br>
 *
 *
 * cacert - returns ca certificate in PEM-format
 * nscacert - returns ca certificate for Netscape/Mozilla
 * iecacert - returns ca certificate for Internet Explorer
 *
 * cacert, nscacert and iecacert also takes optional parameter level=<int 1,2,...>, where the level is
 * which ca certificate in a hierachy should be returned. 0=root (default), 1=sub to root etc.
 *
 * @version $Id: CACertServlet.java,v 1.5 2002-07-20 18:40:08 herrvendil Exp $
 *
 */
public class CACertServlet extends HttpServlet {

    static private Category cat = Category.getInstance(CACertServlet.class.getName() );

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_NSCACERT = "nscacert";
    private static final String COMMAND_IECACERT = "iecacert";
    private static final String COMMAND_CACERT = "cacert";

    private static final String LEVEL_PROPERTY = "level";

    private InitialContext ctx = null;
    ISignSessionHome signhome = null;

    public void init(ServletConfig config) throws ServletException {
    super.init(config);
       try {

            // Get EJB context and home interfaces
            ctx = new InitialContext();

            signhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException {
        cat.debug(">doPost()");
        res.setContentType("text/html");
        res.getOutputStream().println("The certificate/CRL distribution servlet only handles GET method.");
        cat.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        cat.debug(">doGet()");
        // Check if authorized
        EjbcaWebBean ejbcawebbean= (se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), "se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean");
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+"se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean", exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

        try{
          ejbcawebbean.initialize(req);
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_NSCACERT) || command.equalsIgnoreCase(COMMAND_IECACERT) || command.equalsIgnoreCase(COMMAND_CACERT) ) {
            String lev = req.getParameter(LEVEL_PROPERTY);
            int level = 0;
            if (lev != null)
                level = Integer.parseInt(lev);
            // Root CA is level 0, next below root level 1 etc etc
            try {
                ISignSessionRemote ss = signhome.create();
                Certificate[] chain = ss.getCertificateChain();
                // chain.length-1 is last cert in chain (root CA)
                if ( (chain.length-1-level) < 0 ) {
                    PrintStream ps = new PrintStream(res.getOutputStream());
                    ps.println("No CA certificate of level "+level+"exist.");
                    cat.error("No CA certificate of level "+level+"exist.");
                    return;
                }
                X509Certificate cacert = (X509Certificate)chain[chain.length-1-level];
                byte[] enccert = cacert.getEncoded();
                if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
                    res.setContentType("application/x-x509-ca-cert");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    cat.debug("Sent CA cert to NS client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
                    res.setHeader("Content-disposition", "attachment; filename=ca.crt");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    cat.debug("Sent CA cert to IE client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
                    byte[] b64cert = Base64.encode(enccert);
                    String out = "-----BEGIN CERTIFICATE-----\n";
                    out += new String(b64cert);
                    out += "\n-----END CERTIFICATE-----\n";
                    res.setHeader("Content-disposition", "attachment; filename=ca.pem");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(out.length());
                    res.getOutputStream().write(out.getBytes());
                    cat.debug("Sent CA cert to client, len="+out.length()+".");
                } else {
                    res.setContentType("text/plain");
                    res.getOutputStream().println("Commands="+COMMAND_NSCACERT+" || "+COMMAND_IECACERT+" || "+COMMAND_CACERT);
                    return;
                }
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                e.printStackTrace(ps);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificates.");
                cat.error("Error getting CA certificates.");
                cat.error(e);
                return;
            }
        }
        else {
            res.setContentType("text/plain");
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Commands=lastcert | listcerts | crl | revoked");
            return;
        }

    } // doGet

    /**
     * Prints debug info back to browser client
     **/
    private class Debug {
        final private ByteArrayOutputStream buffer;
        final private PrintStream printer;
        Debug( ){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);

            print("<html>");
            print("<body>");
            print("<head>");

            String title = "Certificate/CRL distribution servlet";
            print("<title>" + title + "</title>");
            print("</head>");
            print("<body bgcolor=\"white\">");

            print("<h2>" + title + "</h2>");
        }

        void printDebugInfo(OutputStream out) throws IOException {
            print("</body>");
            print("</html>");
            out.write(buffer.toByteArray());
        }

        void print(Object o) {
            printer.println(o);
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
        }
    }
}
