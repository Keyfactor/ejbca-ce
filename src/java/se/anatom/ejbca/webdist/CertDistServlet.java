
package se.anatom.ejbca.webdist;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Date;
import java.security.cert.*;
import java.math.BigInteger;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import se.anatom.ejbca.util.Base64;

import org.apache.log4j.*;

import se.anatom.ejbca.ca.store.ICertificateStoreSession;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.util.CertTools;

/**
 * Servlet used to distribute certificates and CRLs.<br>
 *
 * The servlet is called with method GET and syntax 'command=<command>'.
 * <p>The follwing commads are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 * <li>lastcert - gets latest certificate of a user, takes argument 'subject=<subjectDN>'.
 * <li>listcerts - lists all certificates of a user, takes argument 'subject=<subjectDN>'.
 * <li>revoked - checks if a certificate is revoked, takes arguments 'subject=<subjectDN>&serno=<serial number>'.
 * </ul>
 *
 * @version $Id: CertDistServlet.java,v 1.2 2002-01-06 10:51:32 anatom Exp $
 *
 */
public class CertDistServlet extends HttpServlet {

    static private Category cat = Category.getInstance( CertDistServlet.class.getName() );

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String COMMAND_REVOKED = "revoked";
    private static final String COMMAND_CERT = "lastcert";
    private static final String COMMAND_LISTCERT = "listcerts";
    private static final String SUBJECT_PROPERTY = "subject";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String SERNO_PROPERTY = "serno";

    private InitialContext ctx = null;
    ICertificateStoreSessionHome home = null;

    public void init(ServletConfig config) throws ServletException {
    super.init(config);
        try {

            // Get EJB context and home interfaces
            ctx = new InitialContext();
            home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
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

        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CRL)) {
            try {
                ICertificateStoreSession store = home.create();
                byte[] crl = store.getLastCRL();
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = x509crl.getIssuerDN().toString();
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                res.setContentType("application/octet-stream");
                res.setContentLength(crl.length);
                res.getOutputStream().write(crl);
                cat.info("Sent latest CRL to client at " + remoteAddr);
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting latest CRL.");
                e.printStackTrace(ps);
                cat.error("Error sending latest CRL to " + remoteAddr);
                cat.error(e);
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_CERT) || command.equalsIgnoreCase(COMMAND_LISTCERT)) {
            String dn = req.getParameter(SUBJECT_PROPERTY);
            if (dn == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=cert?subject=<subjectdn>.");
                cat.debug("Bad request, no 'dn' arg to 'lastcert' or 'listcert' command.");
                return;
            }
            try {
                cat.debug("Looking for certificates for '"+dn+"'.");
                ICertificateStoreSession store = home.create();
                Certificate[] certs = store.findCertificatesBySubject(dn);
                int latestcertno = -1;
                if (command.equalsIgnoreCase(COMMAND_CERT)) {
                    long maxdate = 0;
                    for (int i=0;i<certs.length;i++) {
                        if (i == 0) {
                            maxdate = ((X509Certificate)certs[i]).getNotBefore().getTime();
                            latestcertno = 0;
                        }
                        else if ( ((X509Certificate)certs[i]).getNotBefore().getTime() > maxdate ) {
                            maxdate = ((X509Certificate)certs[i]).getNotBefore().getTime();
                            latestcertno = i;
                        }
                    }
                    if (latestcertno > -1) {
                        byte[] cert = certs[latestcertno].getEncoded();
                        String filename = CertTools.getPartFromDN(dn,"CN")+".cer";
                        res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                        res.setContentType("application/octet-stream");
                        res.setContentLength(cert.length);
                        res.getOutputStream().write(cert);
                        cat.info("Sent latest certificate for '"+dn+"' to client at " + remoteAddr);
                        
                    } else {
                        res.sendError(HttpServletResponse.SC_NOT_FOUND, "No certificate found for requested subject '"+dn+"'.");
                        cat.debug("No certificate found for '"+dn+"'.");
                    }
                }
                if (command.equalsIgnoreCase(COMMAND_LISTCERT)) {
                    res.setContentType("text/html");
                    PrintWriter pout = new PrintWriter(res.getOutputStream());
                    pout.println("<html><head><title>Certificates for "+dn+"</title></head>");
                    pout.println("<body><p>");
                    for (int i=0;i<certs.length;i++) {
                        Date notBefore = ((X509Certificate)certs[i]).getNotBefore();
                        Date notAfter = ((X509Certificate)certs[i]).getNotAfter();
                        String subject = ((X509Certificate)certs[i]).getSubjectDN().toString();
                        String issuer = ((X509Certificate)certs[i]).getIssuerDN().toString();
                        BigInteger serno = ((X509Certificate)certs[i]).getSerialNumber();
                        pout.println("<pre>Subject:"+subject);
                        pout.println("Issuer:"+issuer);
                        pout.println("NotBefore:"+notBefore.toString());
                        pout.println("NotAfter:"+notAfter.toString());
                        pout.println("Serial number:"+serno.toString());
                        pout.println("</pre>");
                        pout.println("<a href=\"certdist?cmd=revoked&issuer="+issuer+"&serno="+serno.toString()+"\">Check if certificate is revoked</a>");
                        pout.println("<hr>");
                        
                    }
                    if (certs.length == 0) {
                        pout.println("No certificates exists for '"+dn+"'.");
                    }
                    pout.println("</body></html>");
                    pout.close();
                }
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                e.printStackTrace(ps);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
                cat.error("Error getting certificates for '"+dn+"' for "+remoteAddr);
                cat.error(e);
                return;
            }

        } else if (command.equalsIgnoreCase(COMMAND_REVOKED)) {
            String dn = req.getParameter(ISSUER_PROPERTY);
            if (dn == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<subjectdn>&serno=<serianlnumber>.");
                cat.debug("Bad request, no 'issuer' arg to 'revoked' command.");
                return;
            }
            String serno = req.getParameter(SERNO_PROPERTY);
            if (serno == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<subjectdn>&serno=<serianlnumber>.");
                cat.debug("Bad request, no 'serno' arg to 'revoked' command.");
                return;
            }
            cat.debug("Looking for certificate for '"+dn+"' and serno='"+serno+"'.");
            try {
                ICertificateStoreSession store = home.create();
                RevokedCertInfo revinfo = store.isRevoked(dn, new BigInteger(serno));
                res.setContentType("text/html");
                PrintWriter pout = new PrintWriter(res.getOutputStream());
                pout.println("<html><head><title>Check revocation</title></head>");
                pout.println("<body><p>");
                if (revinfo != null) {
                    pout.println("<h1>REVOKED</h1>");
                    pout.println("Certificate with issuer '"+dn+"' and serial number '"+serno+"' is revoked");
                    pout.println("RevocationDate is '"+revinfo.getRevocationDate()+"' and reason '"+revinfo.getReason()+"'.");
                } else {
                    pout.println("<h1>NOT REVOKED</h1>");
                    pout.println("Certificate with issuer '"+dn+"' and serial number '"+serno+"' is NOT revoked");
                }
                pout.println("</body></html>");
                pout.close();
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                e.printStackTrace(ps);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error checking revocation.");
                cat.error("Error checking revocation for '"+dn+"' with serno '"+serno+"'.");
                cat.error(e);
                return;
            }                
        } else {
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
