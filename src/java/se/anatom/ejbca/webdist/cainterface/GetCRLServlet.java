package se.anatom.ejbca.webdist.cainterface;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.*;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.log.Admin;

import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;

/**
 * Servlet used to distribute  CRLs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>command=&lt;command&gt;</code>.
 * <p>The follwing commands are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 *
 * @version $Id: GetCRLServlet.java,v 1.11 2003-02-03 13:54:36 scop Exp $
 */
public class GetCRLServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(GetCRLServlet.class.getName() );

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";

    private InitialContext ctx = null;
    private ICertificateStoreSessionHome storehome = null;


    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {

            // Get EJB context and home interfaces

            ctx = new InitialContext();

        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");

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
          ejbcawebbean.initialize(req, "/ca_functionallity/basic_functions");
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

        try{
          if(storehome == null){
            storehome = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
              ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
          }
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }
        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CRL)) {
            try {
                Admin admin = new Admin(((X509Certificate[]) req.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
                ICertificateStoreSessionRemote store = storehome.create();
                byte[] crl = store.getLastCRL(admin);
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = x509crl.getIssuerDN().toString();
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                res.setContentType("application/pkix-crl");
                res.setContentLength(crl.length);
                res.getOutputStream().write(crl);
                log.info("Sent latest CRL to client at " + remoteAddr);
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting latest CRL.");
                e.printStackTrace(ps);
                log.error("Error sending latest CRL to " + remoteAddr, e);
                return;
            }
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
