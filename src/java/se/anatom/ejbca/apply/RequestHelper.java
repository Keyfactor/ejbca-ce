package se.anatom.ejbca.apply;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

import javax.servlet.ServletContext;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;

import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.CertTools;

/**
 * Helper class for hadnling certificate request from browsers or general PKCS#10
 */
public class RequestHelper {
    private static Logger log = Logger.getLogger(RequestHelper.class);
    private Admin administrator;
    private ServletDebug debug;
    private static final Pattern CLASSID = Pattern.compile("\\$CLASSID");

    /**
     * Creates a new RequestHelper object.
     *
     * @param administrator Admin doing the request
     * @param debug object to send debug to
     */
    public RequestHelper(Admin administrator, ServletDebug debug) {
        this.administrator = administrator;
        this.debug = debug;
    }

    /**
     * Handles NetScape certificate request (KEYGEN), these are constructed as: <code>
     * SignedPublicKeyAndChallenge ::= SEQUENCE { publicKeyAndChallenge    PublicKeyAndChallenge,
     * signatureAlgorithm   AlgorithmIdentifier, signature        BIT STRING }</code> PublicKey's
     * encoded-format has to be RSA X.509.
     *
     * @param signsession EJB session to signature bean.
     * @param reqBytes buffer holding te request from NS.
     * @param username username in EJBCA for authoriation.
     * @param password users password for authorization.
     *
     * @return byte[] containing DER-encoded certificate.
     */
    public byte[] nsCertRequest(ISignSessionRemote signsession, byte[] reqBytes, String username,
        String password) throws Exception {
        byte[] buffer = Base64.decode(reqBytes);

        if (buffer == null) {
            return null;
        }

        DERInputStream in = new DERInputStream(new ByteArrayInputStream(buffer));
        ASN1Sequence spkac = (ASN1Sequence) in.readObject();
        in.close();

        NetscapeCertRequest nscr = new NetscapeCertRequest(spkac);

        // Verify POPO, we don't care about the challenge, it's not important.
        nscr.setChallenge("challenge");

        if (nscr.verify("challenge") == false) {
            throw new SignRequestSignatureException(
                "Invalid signature in NetscapeCertRequest, popo-verification failed.");
        }

        log.debug("POPO verification successful");

        X509Certificate cert = (X509Certificate) signsession.createCertificate(administrator,
                username, password, nscr.getPublicKey());

        //Certificate[] chain = ss.getCertificateChain();
        byte[] pkcs7 = signsession.createPKCS7(administrator, cert);
        log.debug("Created certificate (PKCS7) for " + username);
        debug.print("<h4>Generated certificate:</h4>");
        debug.printInsertLineBreaks(cert.toString().getBytes());

        return pkcs7;
    }

    //nsCertRequest

    /**
     * Handles PKCS10 certificate request, these are constructed as: <code> CertificationRequest
     * ::= SEQUENCE { certificationRequestInfo  CertificationRequestInfo, signatureAlgorithm
     * AlgorithmIdentifier{{ SignatureAlgorithms }}, signature                       BIT STRING }
     * CertificationRequestInfo ::= SEQUENCE { version             INTEGER { v1(0) } (v1,...),
     * subject             Name, subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
     * attributes          [0] Attributes{{ CRIAttributes }}} SubjectPublicKeyInfo { ALGORITHM :
     * IOSet} ::= SEQUENCE { algorithm           AlgorithmIdentifier {{IOSet}}, subjectPublicKey
     * BIT STRING }</code> PublicKey's encoded-format has to be RSA X.509.
     *
     * @param signsession signsession to get certificate from
     * @param b64Encoded base64 encoded pkcs10 request message
     * @param username username of requesting user
     * @param password password of requesting user
     *
     * @return Base64 encoded PKCS7
     */
    public byte[] pkcs10CertRequest(ISignSessionRemote signsession, byte[] b64Encoded,
        String username, String password) throws Exception {
        X509Certificate cert=null;
        byte[] buffer;

        try {
            // A real PKCS10 PEM request
            String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
            String endKey = "-----END CERTIFICATE REQUEST-----";
            buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
        } catch (IOException e) {
            try {
                // Keytool PKCS10 PEM request
                String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
                String endKey = "-----END NEW CERTIFICATE REQUEST-----";
                buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
            } catch (IOException ioe) {
                // IE PKCS10 Base64 coded request
                buffer = Base64.decode(b64Encoded);
            }
        }

        if (buffer == null) {
            return null;
        }
        PKCS10RequestMessage req = new PKCS10RequestMessage(buffer);
        req.setUsername(username);
        req.setPassword(password);
        IResponseMessage resp = signsession.createCertificate(administrator,req,Class.forName("se.anatom.ejbca.protocol.X509ResponseMessage"));
        cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        byte[] pkcs7 = signsession.createPKCS7(administrator, cert);
        log.debug("Created certificate (PKCS7) for " + username);
        debug.print("<h4>Generated certificate:</h4>");
        debug.printInsertLineBreaks(cert.toString().getBytes());
        return Base64.encode(pkcs7);
    }

    //ieCertRequest

    /**
     * Formats certificate in form to be received by IE
     *
     * @param bA input
     * @param out Output
     */
    public static void ieCertFormat(byte[] bA, PrintStream out)
        throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bA)));
        int rowNr = 0;

        while (true) {
            String line = br.readLine();

            if (line == null) {
                break;
            }

            if (line.indexOf("END CERT") < 0) {
                if (line.indexOf(" CERT") < 0) {
                    if (++rowNr > 1) {
                        out.println(" & _ ");
                    } else {
                        out.print("    cert = ");
                    }

                    out.print('\"' + line + '\"');
                }
            } else {
                break;
            }
        }

        out.println();
    }

    /**
     * Reads template and inserts cert to send back to IE for installation of cert
     *
     * @param b64cert cert to be installed in IE-client
     * @param out utput stream to send to
     * @param sc serveltcontext
     * @param responseTemplate path to responseTemplate
     * @param classid replace
     *
     * @throws Exception on error
     */
    public static void sendNewCertToIEClient(byte[] b64cert, OutputStream out, ServletContext sc,
        String responseTemplate, String classid) throws Exception {
        if (b64cert.length == 0) {
            log.error("0 length certificate can not be sent to IE client!");

            return;
        }

        PrintStream ps = new PrintStream(out);
        BufferedReader br = new BufferedReader(new InputStreamReader(sc.getResourceAsStream(
                        responseTemplate)));

        while (true) {
            String line = br.readLine();

            if (line == null) {
                break;
            }

            if (line.indexOf("cert =") < 0) {
                ps.println(CLASSID.matcher(line).replaceFirst(classid));
            } else {
                RequestHelper.ieCertFormat(b64cert, ps);
            }
        }

        ps.close();
        log.debug("Sent reply to IE client");
        log.debug(new String(b64cert));
    }

    /**
     * Sends back cert to NS/Mozilla for installation of cert
     *
     * @param certs DER encoded certificates to be installed in browser
     * @param out output stream to send to
     *
     * @throws Exception on error
     */
    public static void sendNewCertToNSClient(byte[] certs, HttpServletResponse out)
        throws Exception {
        if (certs.length == 0) {
            log.error("0 length certificate can not be sent to NS client!");

            return;
        }

        // Set content-type to what NS wants
        out.setContentType("application/x-x509-user-cert");
        out.setContentLength(certs.length);

        // Print the certificate
        out.getOutputStream().write(certs);
        log.debug("Sent reply to NS client");
        log.debug(new String(Base64.encode(certs)));
    }

    /**
     * Sends back certificate as binary file (application/octet-stream)
     *
     * @param b64cert base64 encoded certificate to be returned
     * @param out output stream to send to
     *
     * @throws Exception on error
     */
    public static void sendNewB64Cert(byte[] b64cert, HttpServletResponse out)
        throws Exception {
        if (b64cert.length == 0) {
            log.error("0 length certificate can not be sent to client!");

            return;
        }

        // Set content-type to general file
        out.setContentType("application/octet-stream");
        out.setHeader("Content-disposition", "filename=cert.pem");

        String beg = "-----BEGIN CERTIFICATE-----\n";
        String end = "\n-----END CERTIFICATE-----\n";
        out.setContentLength(b64cert.length + beg.length() + end.length());

        // Write the certificate
        ServletOutputStream os = out.getOutputStream();
        os.write(beg.getBytes());
        os.write(b64cert);
        os.write(end.getBytes());
        out.flushBuffer();
        log.debug("Sent reply to client");
        log.debug(new String(b64cert));
    }

    /**
     * Sends back CA-certificate as binary file (application/x-x509-ca-cert)
     *
     * @param cert DER encoded certificate to be returned
     * @param out output stream to send to
     *
     * @throws Exception on error
     */
    public static void sendNewX509CaCert(byte[] cert, HttpServletResponse out)
        throws Exception {
        // Set content-type to CA-cert
        sendBinaryBytes(cert, out, "application/x-x509-ca-cert");
    }

    /**
     * Sends back a number of bytes
     *
     * @param bytes DER encoded certificate to be returned
     * @param out output stream to send to
     * @param contentType mime type to send back bytes as
     *
     * @throws Exception on error
     */
    public static void sendBinaryBytes(byte[] bytes, HttpServletResponse out, String contentType)
        throws Exception {
        if (bytes.length == 0) {
            log.error("0 length can not be sent to client!");

            return;
        }

        // Set content-type to general file
        out.setContentType(contentType);
        out.setContentLength(bytes.length);

        // Write the certificate
        ServletOutputStream os = out.getOutputStream();
        os.write(bytes);
        out.flushBuffer();
        log.debug("Sent " + bytes.length + " bytes to client");
    }
}
