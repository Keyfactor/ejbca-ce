package se.anatom.ejbca.samples;

import java.io.*;
import java.net.*;
// Use for SSL connections
/*
import javax.net.ssl.*;
import com.sun.net.ssl.*;
*/

import java.security.KeyPair;
import java.security.cert.*;
import java.security.Provider;
import java.security.Security;

import org.apache.log4j.*;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;

import se.anatom.ejbca.util.*;

/**
 * NOTE: Support for SSL has been commented out in this sample, since it requires JSSE.
 *
 * This sample class generates a PKCS10 request and POSTs to the CAs web interface.
 * The reply is received and printed to stdout.
 *
 * Takes arguments:
 * <ul>
 * <li>requesturl - URL to the CA web (servlet where requests are POSTed), http://127.0.0.1/apply/apply_man.jsp.
 * <li>username - username of a user registered with the CA with status NEW.
 * <li>password - password for the above user.
 * </ul>
 *
 * @version $Id: HttpGetCert.java,v 1.6 2003-01-12 17:16:32 anatom Exp $
 *
 */
public class HttpGetCert {

    private static Category cat = Category.getInstance(HttpGetCert.class.getName());

    private X509Certificate webcert = null;

    /**
     * Constructor
     */
    public HttpGetCert() throws java.io.IOException {
        cat.debug(">HttpGetCert:");

        // Use for SSL connections
        /*
        System.setProperty("java.protocol.handler.pkgs","com.sun.net.ssl.internal.www.protocol");
        java.security.Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        */
        cat.debug("<HttpGetCert:");
    } // HttpGetCert

    /**
     * Sets the CA certificate used to verify the web server's certificate. We only support a single self-signed CA certificate here.
     *
     * @param cert servercertificate
     * @exception java.security.cert.CertificateException if the certificate is not correct.
     * @throws IllegalArgumentException if webcert is not a self-signed certificate
     */
        // Use for SSL connections
        /*
    public void setSSLTrustedServerCert(byte[] cert) throws java.security.cert.CertificateException {
        cat.debug(">setSSLTrustedServerCert:");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        webcert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert));
        if ( CertTools.isSelfSigned( webcert ) )
            throw new IllegalArgumentException("Webcert certificate is not self signed (not a root CA certificate).");
        cat.debug("<setSSLTrustedServerCert:");

    } // setSSLTrustedServerCert
    */

    /**
     * Creates a SSLSocketFactory to communicate with the server using HTTPS.
     * @throws IllegalArgumentException if webcert is not set.
     * @throws Exception error in setting up SSLContext.
     */
    // Use for SSL connections
    /*
    private SSLSocketFactory getSSLFactory() throws IllegalArgumentException, Exception {
        cat.debug( ">getSSLFactory" );
        SSLContext ctx = SSLContext.getInstance( "SSL" );
        KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
        String proxyHost = null;
        String proxyPort = null;

        // if we are behind a proxy, there must be set
        if (proxyHost != null)
            System.setProperty("https.proxyHost", proxyHost);
        if (proxyPort != null)
            System.setProperty("https.proxyPort", proxyPort);

        if (webcert == null)
            throw new IllegalArgumentException("Server certificate must be set for SSL communication");

        // If we must use client certificates here, we should read some certs and keys and create a keystore to put in the KeyManagerFactory

        // Make a truststore to verify the server
        KeyStore trustks = KeyStore.getInstance( "jks" );
        trustks.load( null, new String("foo123").toCharArray() );
        trustks.setCertificateEntry( "trustedRootCA", webcert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init( trustks );

        ctx.init( null, tmf.getTrustManagers(), null );

        cat.debug( "<getSSLFactory" );
        return ctx.getSocketFactory();
    }
    */

    /**
     * Creates a URLConnection either HTTP or HTTPS.
     * @param URL the URL (http:// or https://
     * @return URLConnection
     */
    private URLConnection getUrlConnection(URL url) throws Exception {
        URLConnection con = url.openConnection();
       // Use for SSL connections
        /*
        if( con instanceof HttpsURLConnection ) {
            HttpsURLConnection httpscon = (HttpsURLConnection) con;
            httpscon.setSSLSocketFactory( getSSLFactory() );
        }
        */
        return con;
    }

    /**
     * Sends a certificate request (PKCS10) to the CA and receives the reply.
     *
     * @param request Base64 encoded PKCS10-request (PEM-format)
     * @param username username
     * @param password password
     * @return byte array with received certificate
     * @exception IllegalArgumentException if requesturl is not a vlid HTTP or HTTPS url.
     * @exception Exception if the trusted webcert is not a correct certificate.
     * @exception Exception if we get back a HTTP response code != 200 from the CA.
     * @exception Exception if the reply is not a correct certificate.
     */
    public void sendHttpReq(String requestUrl, String request, String username, String password)
    throws Exception {
        cat.debug(">sendHttpReq: request=" + request.toString() + ", username=" + username + ", password=" + password);
        if (requestUrl == null)
            throw new IllegalArgumentException("requesturl can not be  null.");

        cat.debug("Sending request to: " + requestUrl);

        URL url = new URL(requestUrl);
        HttpURLConnection con = (HttpURLConnection)getUrlConnection(url);
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        PrintWriter out = new PrintWriter(con.getOutputStream());
        out.println("pkcs10req=" + URLEncoder.encode(request) +
        "&user=" + URLEncoder.encode(username) +
        "&password=" + URLEncoder.encode(password) +
        "&submit=Submit+Query");
        out.close();

        // Read the reqponse
        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
        }
        if (con.getResponseCode() == 200)
            cat.debug("Received certificate reply.");
        else
            throw new Exception("Error sending PKCS10-request.");

        // We are done, disconnect
        con.disconnect();

        cat.debug("<sendHttpReq:");

    } // sendHttpReq

    public static void main(String args[])  throws Exception {
        //Configure Log4j
        BasicConfigurator.configure();
        // Install BouncyCastle provider
        Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        int result = Security.addProvider(BCJce);

        // Generate keys (512 bit for sample purposes)
        System.out.print("Generating 512 bit RSA keys.");
        KeyPair rsaKeys = KeyTools.genKeys(512);
        System.out.println("Keys generated.");
        // Generate PKCS10 certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("C=SE,O=AnaTom,CN=HttpTest"), rsaKeys.getPublic(), null, rsaKeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
        bos1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        bos1.write(Base64.encode(bOut.toByteArray()));
        bos1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        bos1.close();
        System.out.println("CertificationRequest generated:");
        System.out.println(new String(bos1.toByteArray()));

        // Now send the request
        System.out.println("Trying to send request...");
        HttpGetCert getter = new HttpGetCert();
        getter.sendHttpReq("http://127.0.0.1:8080/apply/certreq", new String(bos1.toByteArray()), "foo", "foo123");
    }

}  // class CertRequest
