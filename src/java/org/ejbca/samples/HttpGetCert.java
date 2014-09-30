/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.samples;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyPair;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;



/**
 * Example how a certificate can be fetched programmatically using HTTP/S. The sample generates a 
 * certificate request and uses POST to the same servlet as used from a browser through
 * http://127.0.0.1:8080/ejbca/publicweb/apply/apply_man.jsp.
 * The servlet url used in the example is
 * http://127.0.0.1:8080/ejbca/publicweb/apply/certreq.
 * The certificate reply containing a PEM-formatted certificate is printed to the screen.
 * 
 * NOTE: Support for SSL has been commented out in this sample, since it requires JSSE. This sample
 * class generates a PKCS10 request and POSTs to the CAs web interface. The reply is received and
 * printed to stdout. Takes arguments:
 * 
 * <ul>
 * <li>
 * requesturl - URL to the CA web (servlet where requests are POSTed),
 * http://127.0.0.1/apply/apply_man.jsp.
 * </li>
 * <li>
 * username - username of a user registered with the CA with status NEW.
 * </li>
 * <li>
 * password - password for the above user.
 * </li>
 * </ul>
 *
 * @version $Id$
 */
public class HttpGetCert {
    private static Logger log = Logger.getLogger(HttpGetCert.class);

    /**
     * Constructor
     */
    public HttpGetCert() {
        log.trace(">HttpGetCert:");

        // Use for SSL connections
        /*
        System.setProperty("java.protocol.handler.pkgs","com.sun.net.ssl.internal.www.protocol");
        java.security.Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        */
        log.trace("<HttpGetCert:");
    }

    // HttpGetCert

    /**
     * Sets the CA certificate used to verify the web server's certificate. We only support a
     * single self-signed CA certificate here.
     *
     * @param url servercertificate
     *
     * @return DOCUMENT ME!
     *
     * @exception java.security.cert.CertificateException if the certificate is not correct.
     * @throws IllegalArgumentException if webcert is not a self-signed certificate
     */

    // Use for SSL connections

    /*
    public void setSSLTrustedServerCert(byte[] cert) throws java.security.cert.CertificateException {
    log.trace(">setSSLTrustedServerCert:");
    CertificateFactory cf = CertTools.getCertificateFactory();
    webcert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert));
    if ( CertTools.isSelfSigned( webcert ) )
        throw new IllegalArgumentException("Webcert certificate is not self signed (not a root CA certificate).");
    log.trace("<setSSLTrustedServerCert:");

    } // setSSLTrustedServerCert
    */

    /**
     * Creates a SSLSocketFactory to communicate with the server using HTTPS.
     *
     * @param url DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IllegalArgumentException if webcert is not set.
     * @throws Exception error in setting up SSLContext.
     */

    // Use for SSL connections

    /*
    private SSLSocketFactory getSSLFactory() throws IllegalArgumentException, Exception {
        log.trace( ">getSSLFactory" );
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

        log.trace( "<getSSLFactory" );
        return ctx.getSocketFactory();
    }
    */

    /**
     * Creates a URLConnection either HTTP or HTTPS.
     *
     * @param url the URL (http:// or https://
     *
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
     * @param requestUrl DOCUMENT ME!
     * @param request Base64 encoded PKCS10-request (PEM-format)
     * @param username username
     * @param password password
     *
     * @exception IllegalArgumentException if requesturl is not a vlid HTTP or HTTPS url.
     * @exception Exception if the trusted webcert is not a correct certificate.
     * @exception Exception if we get back a HTTP response code != 200 from the CA.
     * @exception Exception if the reply is not a correct certificate.
     */
    public void sendHttpReq(String requestUrl, String request, String username, String password)
        throws Exception {
        log.trace(">sendHttpReq: request=" + request.toString() + ", username=" + username +
            ", password=" + password);

        if (requestUrl == null) {
            throw new IllegalArgumentException("requesturl can not be  null.");
        }

        log.debug("Sending request to: " + requestUrl);

        URL url = new URL(requestUrl);
        HttpURLConnection con = (HttpURLConnection) getUrlConnection(url);

        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        PrintWriter out = new PrintWriter(con.getOutputStream());
        out.println("pkcs10req=" + URLEncoder.encode(request,"UTF-8") + "&user=" +
            URLEncoder.encode(username,"UTF-8") + "&password=" + URLEncoder.encode(password,"UTF-8") +
            "&submit=Submit+Query");
        out.close();

        // Read the reqponse
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;

            while ((inputLine = in.readLine()) != null) {
                System.out.println(inputLine);
            }        	
        } finally {
        	if (in != null) {
        		in.close();
        	}
        }

        if (con.getResponseCode() == 200) {
            log.debug("Received certificate reply.");
        } else {
            throw new Exception("Error sending PKCS10-request.");
        }

        // We are done, disconnect
        con.disconnect();

        log.trace("<sendHttpReq:");
    }

    // sendHttpReq

    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public static void main(String[] args) throws Exception {
        //Configure Log4j
        BasicConfigurator.configure();

        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();

        // Generate keys (512 bit for sample purposes)
        System.out.print("Generating 512 bit RSA keys.");

        KeyPair rsaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        System.out.println("Keys generated.");

        // Generate PKCS10 certificate request
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX500Name("C=SE,O=AnaTom,CN=HttpTest"), rsaKeys.getPublic(),
                new DERSet(), rsaKeys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req.toASN1Structure());
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
        getter.sendHttpReq("http://127.0.0.1:8080/apply/certreq", new String(bos1.toByteArray()),
            "foo", "foo123");
    }
}


// class CertRequest
