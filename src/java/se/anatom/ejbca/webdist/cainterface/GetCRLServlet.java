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
 
package se.anatom.ejbca.webdist.cainterface;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.CertTools;
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
 * @version $Id: GetCRLServlet.java,v 1.20 2005-02-09 08:30:54 anatom Exp $
 */
public class GetCRLServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(GetCRLServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String ISSUER_PROPERTY = "issuer";

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
          ejbcawebbean.initialize(req, "/ca_functionality/basic_functions");
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
        
        String issuerdn = null; 
        if(req.getParameter(ISSUER_PROPERTY) != null){
          issuerdn = java.net.URLDecoder.decode(req.getParameter(ISSUER_PROPERTY),"UTF-8");
        }
        
        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CRL) && issuerdn != null) {
            try {
                Admin admin = new Admin(((X509Certificate[]) req.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
                ICertificateStoreSessionRemote store = storehome.create();
                byte[] crl = store.getLastCRL(admin, issuerdn);
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = CertTools.getIssuerDN(x509crl);
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                if (res.containsHeader("Pragma")) {
                    log.debug("Removing Pragma header to avoid caching issues in IE");
                    res.setHeader("Pragma",null);
                }
                if (res.containsHeader("Cache-Control")) {
                    log.debug("Removing Cache-Control header to avoid caching issues in IE");
                    res.setHeader("Cache-Control",null);
                }
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
        private final ByteArrayOutputStream buffer;
        private final PrintStream printer;
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
