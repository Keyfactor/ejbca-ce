package se.anatom.ejbca.webdist;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Date;
import java.util.Collection;
import java.security.cert.*;
import java.math.BigInteger;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import se.anatom.ejbca.util.Base64;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.log.Admin;

/**
 * Servlet used to distribute certificates and CRLs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>command=&lt;command&gt;</code>.
 * <p>The follwing commands are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 * <li>lastcert - gets latest certificate of a user, takes argument 'subject=<subjectDN>'.
 * <li>listcerts - lists all certificates of a user, takes argument 'subject=<subjectDN>'.
 * <li>revoked - checks if a certificate is revoked, takes arguments 'subject=<subjectDN>&serno=<serial number>'.
 * <li>cacert - returns ca certificate in PEM-format
 * <li>nscacert - returns ca certificate for Netscape/Mozilla
 * <li>iecacert - returns ca certificate for Internet Explorer
 * </ul>
 * cacert, nscacert and iecacert also takes optional parameter level=<int 1,2,...>, where the level is
 * which ca certificate in a hierachy should be returned. 0=root (default), 1=sub to root etc.
 *
 * @version $Id: CertDistServlet.java,v 1.19 2003-09-27 09:05:55 anatom Exp $
 */
public class CertDistServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(CertDistServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String COMMAND_REVOKED = "revoked";
    private static final String COMMAND_CERT = "lastcert";
    private static final String COMMAND_LISTCERT = "listcerts";
    private static final String COMMAND_NSCACERT = "nscacert";
    private static final String COMMAND_IECACERT = "iecacert";
    private static final String COMMAND_CACERT = "cacert";
    
    private static final String SUBJECT_PROPERTY = "subject";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String SERNO_PROPERTY = "serno";
    private static final String LEVEL_PROPERTY = "level";

    private ICertificateStoreSessionHome storehome = null;
    private ISignSessionHome signhome = null;

    /**
     * init servlet
     *
     * @param config servlet configuration
     *
     * @throws ServletException error
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {

            // Get EJB context and home interfaces
            InitialContext ctx = new InitialContext();
            storehome = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
            signhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    /**
     * handles http post
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

	/**
	 * handles http get
	 *
	 * @param req servlet request
	 * @param res servlet response
	 *
	 * @throws IOException input/output error
	 * @throws ServletException error
	 */
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");

        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);

        String issuerdn = null; 
        if(req.getParameter(ISSUER_PROPERTY) != null){
          issuerdn = java.net.URLDecoder.decode(req.getParameter(ISSUER_PROPERTY),"UTF-8");
        }        
        
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CRL) && issuerdn != null) {
            try {
                ICertificateStoreSessionRemote store = storehome.create();
                byte[] crl = store.getLastCRL(administrator, issuerdn);
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = CertTools.getIssuerDN(x509crl);
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                res.setContentType("application/x-x509-crl");
                res.setContentLength(crl.length);
                res.getOutputStream().write(crl);
                log.debug("Sent latest CRL to client at " + remoteAddr);
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting latest CRL.");
                e.printStackTrace(ps);
                log.debug("Error sending latest CRL to " + remoteAddr);
                log.debug(e);
                return;
            }
        } else if ((command.equalsIgnoreCase(COMMAND_CERT) || command.equalsIgnoreCase(COMMAND_LISTCERT)) && issuerdn != null) {
            String dn = req.getParameter(SUBJECT_PROPERTY);
            if (dn == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=cert?subject=<subjectdn>&issuer=<issuerdn>.");
                log.debug("Bad request, no 'dn' arg to 'lastcert' or 'listcert' command.");
                return;
            }
            try {
                log.debug("Looking for certificates for '"+dn+"'.");
                ICertificateStoreSessionRemote store = storehome.create();
                Collection certcoll = store.findCertificatesBySubjectAndIssuer(administrator, dn, issuerdn);
                Object[] certs = certcoll.toArray();
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
                        byte[] cert = ((X509Certificate)certs[latestcertno]).getEncoded();
                        String filename = CertTools.getPartFromDN(dn,"CN")+".cer";
                        res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                        res.setContentType("application/octet-stream");
                        res.setContentLength(cert.length);
                        res.getOutputStream().write(cert);
                        log.debug("Sent latest certificate for '"+dn+"' to client at " + remoteAddr);

                    } else {
                        res.sendError(HttpServletResponse.SC_NOT_FOUND, "No certificate found for requested subject '"+dn+"'.");
                        log.debug("No certificate found for '"+dn+"'.");
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
                        String subject = CertTools.getSubjectDN((X509Certificate)certs[i]);
                        String issuer = CertTools.getIssuerDN((X509Certificate)certs[i]);
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
                log.debug("Error getting certificates for '"+dn+"' for "+remoteAddr);
                log.debug(e);
                return;
            }
        } else if ((command.equalsIgnoreCase(COMMAND_NSCACERT) || command.equalsIgnoreCase(COMMAND_IECACERT) || command.equalsIgnoreCase(COMMAND_CACERT)) && issuerdn != null ) {
            String lev = req.getParameter(LEVEL_PROPERTY);
            int level = 0;
            boolean pkcs7 = false;
            if (lev != null)
                level = Integer.parseInt(lev);
            else
                pkcs7 = true;
            // Root CA is level 0, next below root level 1 etc etc, -1 returns chain as PKCS7
            try {
                ISignSessionRemote ss = signhome.create();
                Certificate[] chain = (Certificate[]) ss.getCertificateChain(administrator, issuerdn.hashCode()).toArray(new Certificate[0]);
                // chain.length-1 is last cert in chain (root CA)
                if ( (chain.length-1-level) < 0 ) {
                    PrintStream ps = new PrintStream(res.getOutputStream());
                    ps.println("No CA certificate of level "+level+"exist.");
                    log.debug("No CA certificate of level "+level+"exist.");
                    return;
                }
                X509Certificate cacert = (X509Certificate)chain[chain.length-1-level];
                String filename=CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                if (filename == null)
                    filename = "ca";
                byte[] enccert = null;
                if (pkcs7)
                    enccert = ss.createPKCS7(administrator, null);
                else
                    enccert = cacert.getEncoded();
                if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
                    res.setContentType("application/x-x509-ca-cert");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to NS client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
                    if (pkcs7)
                        res.setHeader("Content-disposition", "attachment; filename="+filename+".p7c");
                    else
                        res.setHeader("Content-disposition", "attachment; filename="+filename+".crt");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to IE client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
                    byte[] b64cert = Base64.encode(enccert);
                    String out;
                    if (pkcs7)
                        out = "-----BEGIN PKCS7-----\n";
                    else
                        out = "-----BEGIN CERTIFICATE-----\n";
                    out += new String(b64cert);
                    if (pkcs7)
                        out += "\n-----END PKCS7-----\n";
                    else
                        out += "\n-----END CERTIFICATE-----\n";
                    res.setHeader("Content-disposition", "attachment; filename="+filename+".pem");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(out.length());
                    res.getOutputStream().write(out.getBytes());
                    log.debug("Sent CA cert to client, len="+out.length()+".");
                } else {
                    res.setContentType("text/plain");
                    res.getOutputStream().println("Commands="+COMMAND_NSCACERT+" || "+COMMAND_IECACERT+" || "+COMMAND_CACERT);
                    return;
                }
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                e.printStackTrace(ps);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificates.");
                log.debug("Error getting CA certificates.");
                log.debug(e);
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_REVOKED)) {
            String dn = req.getParameter(ISSUER_PROPERTY);
            if (dn == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<subjectdn>&serno=<serianlnumber>.");
                log.debug("Bad request, no 'issuer' arg to 'revoked' command.");
                return;
            }
            String serno = req.getParameter(SERNO_PROPERTY);
            if (serno == null) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<subjectdn>&serno=<serianlnumber>.");
                log.debug("Bad request, no 'serno' arg to 'revoked' command.");
                return;
            }
            log.debug("Looking for certificate for '"+dn+"' and serno='"+serno+"'.");
            try {
                ICertificateStoreSessionRemote store = storehome.create();
                RevokedCertInfo revinfo = store.isRevoked(administrator, dn, new BigInteger(serno));
                res.setContentType("text/html");
                PrintWriter pout = new PrintWriter(res.getOutputStream());
                pout.println("<html><head><title>Check revocation</title></head>");
                pout.println("<body><p>");
                if ( (revinfo != null) && (revinfo.getReason() != RevokedCertInfo.NOT_REVOKED) ) {
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
                log.debug("Error checking revocation for '"+dn+"' with serno '"+serno+"'.");
                log.debug(e);
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
