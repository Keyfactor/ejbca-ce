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
 
package org.ejbca.ui.web;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.regex.Pattern;

import javax.ejb.ObjectNotFoundException;
import javax.servlet.ServletContext;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.web.pub.ServletDebug;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Helper class for handling certificate request from browsers or general PKCS#10
 * 
 * @version $Id$
 */
public class RequestHelper {
    private static Logger log = Logger.getLogger(RequestHelper.class);
    private AuthenticationToken administrator;
    private ServletDebug debug;
    private static final Pattern CLASSID = Pattern.compile("\\$CLASSID");

	public static final  String BEGIN_CERTIFICATE_REQUEST_WITH_NL = "-----BEGIN CERTIFICATE REQUEST-----\n";
	public static final  String END_CERTIFICATE_REQUEST_WITH_NL    = "\n-----END CERTIFICATE REQUEST-----\n";

	public static final  String BEGIN_CERTIFICATE_WITH_NL = "-----BEGIN CERTIFICATE-----\n";
	public static final  String END_CERTIFICATE_WITH_NL    = "\n-----END CERTIFICATE-----\n";
    public static final  String BEGIN_CRL_WITH_NL = "-----BEGIN X509 CRL-----\n";
    public static final  String END_CRL_WITH_NL    = "\n-----END X509 CRL-----\n";

	public static final  String BEGIN_PKCS7  = "-----BEGIN PKCS7-----\n";
	public static final  String END_PKCS7     = "\n-----END PKCS7-----\n";	
	public static final  String BEGIN_PKCS7_WITH_NL = "-----BEGIN PKCS7-----\n";
	public static final  String END_PKCS7_WITH_NL    = "\n-----END PKCS7-----\n";
	
	/** @deprecated Since 6.1.0, remove in 7.0.0. Use CertificateResponseType.ENCODED_CERTIFICATE instead */
	@Deprecated
	public static final int ENCODED_CERTIFICATE = 1;
	/** @deprecated Since 6.1.0, remove in 7.0.0. Use CertificateResponseType.ENCODED_PKCS7 instead */
	@Deprecated
	public static final int ENCODED_PKCS7          = 2;
	/** @deprecated Since 6.1.0, remove in 7.0.0. Use CertificateResponseType.BINARY_CERTIFICATE instead */
	@Deprecated
	public static final int BINARY_CERTIFICATE = 3;
	/** @deprecated Since 6.1.0, remove in 7.0.0. Use CertificateResponseType.ENCODED_CERTIFICATE_CHAIN instead */
	@Deprecated
	public static final int ENCODED_CERTIFICATE_CHAIN = 4;
	
    /**
     * Creates a new RequestHelper object.
     *
     * @param administrator Admin doing the request
     * @param debug object to send debug to or null to disable
     */
    public RequestHelper(AuthenticationToken administrator, ServletDebug debug) {
        this.administrator = administrator;
        this.debug = debug;
    }

    /**
     * Handles Firefox certificate request (KEYGEN), these are constructed as: <code>
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
     *
     * @throws CesecoreException 
     * @throws AuthorizationDeniedException 
     * @throws EjbcaException 
     * @throws CADoesntExistsException 
     * @throws ObjectNotFoundException 
     * @throws CertificateEncodingException 
     * @throws NoSuchProviderException 
     * @throws SignatureException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public byte[] nsCertRequest(SignSessionLocal signsession, byte[] reqBytes, String username, String password) throws 
            ObjectNotFoundException, CADoesntExistsException, EjbcaException, AuthorizationDeniedException, CesecoreException,
            CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        byte[] buffer = Base64.decode(reqBytes);

        if (buffer == null) {
            return null;
        }

        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(buffer));
        ASN1Sequence spkac;
        try {
            spkac = (ASN1Sequence) in.readObject();
            in.close();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
       
        NetscapeCertRequest nscr = new NetscapeCertRequest(spkac);

        // Verify POPO, we don't care about the challenge, it's not important.
        nscr.setChallenge("challenge");

        if (nscr.verify("challenge") == false) {
            throw new SignRequestSignatureException(
                "Invalid signature in NetscapeCertRequest, popo-verification failed.");
        }
        if (log.isDebugEnabled()) {
        	log.debug("POPO verification successful");
        }
        X509Certificate cert = (X509Certificate) signsession.createCertificate(administrator,
                username, password, nscr.getPublicKey());
        if (log.isDebugEnabled()) {
        	log.debug("Created certificate for " + username);
        }
        if (debug != null) {
            debug.print("<h4>Generated certificate:</h4>");
            debug.printInsertLineBreaks(cert.toString().getBytes());
        }
        return cert.getEncoded();

/* ECA-2065: the <keygen> specification doesn't say anything about the
 * returned certificate.  Originally EJBCA used a PKCS7 container but
 * this has proved to be incompatible with Safari and Chrome.  ECA-2065
 * changes returned data to just a DER-encoded certificate which has
 * been verified to work in Firefox, Chrome and Safari.  The mime-type
 * remains application/x-x509-user-certificate.  Below is the deleted
 * code: 
        // Don't include certificate chain in the PKCS7 to Firefox
        byte[] pkcs7 = signsession.createPKCS7(administrator, cert, false);
        log.debug("Created certificate (PKCS7) for " + username);
        if (debug != null) {
            debug.print("<h4>Generated certificate:</h4>");
            debug.printInsertLineBreaks(cert.toString().getBytes());
        }

        return pkcs7;
*/
    } //nsCertRequest

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
     * @param caSession a reference to CaSessionBean
     * @param b64Encoded base64 encoded pkcs10 request message
     * @param username username of requesting user
     * @param password password of requesting user
     * @param resulttype should indicate if a PKCS7 or just the certificate is wanted.
     * @param doSplitLines
     * @return Base64 encoded byte[] 
     * @throws AuthorizationDeniedException 
     * @throws CesecoreException 
     * @throws EjbcaException 
     * @throws CertificateException 
     * @throws CertificateEncodingException 
     * @throws CertificateExtensionException if b64Encoded specified invalid extensions
     */
    public CertificateRequestResponse pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            CertificateResponseType resulttype, boolean doSplitLines) throws EjbcaException, CesecoreException, AuthorizationDeniedException,
            CertificateEncodingException, CertificateException, CertificateExtensionException {
        byte[] encoded = null;
        X509Certificate cert = null;
		PKCS10RequestMessage req = RequestMessageUtils.genPKCS10RequestMessage(b64Encoded);
		req.setUsername(username);
        req.setPassword(password);
        ResponseMessage resp = signsession.createCertificate(administrator, req, X509ResponseMessage.class, null);
        cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), X509Certificate.class);
        switch (resulttype) {
        case ENCODED_CERTIFICATE:            
            encoded = Base64.encode(cert.getEncoded(), doSplitLines);
            break;
        case ENCODED_CERTIFICATE_CHAIN:
            CAInfo caInfo = signsession.getCAFromRequest(administrator, req, false).getCAInfo();
            LinkedList<Certificate> chain = new LinkedList<Certificate>(caInfo.getCertificateChain());
            chain.addFirst(cert);
            encoded = CertTools.getPemFromCertificateChain(chain);
            break;
        case ENCODED_PKCS7:
            encoded = Base64.encode(signsession.createPKCS7(administrator, cert, true), doSplitLines);
            break;
        default:           
            break;
        }
        log.debug("Created certificate (PKCS7) for " + username);
        if (debug != null) {
            debug.print("<h4>Generated certificate:</h4>");
            debug.printInsertLineBreaks(cert.toString().getBytes());
        }
        return new CertificateRequestResponse(cert, encoded);
    } //pkcs10CertReq
    
    /**
     * @deprecated Since 6.1.0, remove in 7.0.0. Use the other overloaded version taking a CertificateResponseType in the resulttype parameter.
     */
    @Deprecated
    public byte[] pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            int resulttype, boolean doSplitLines) throws EjbcaException, CesecoreException, AuthorizationDeniedException,
            CertificateEncodingException, CertificateException, IOException, CertificateExtensionException {
        return pkcs10CertRequest(signsession, caSession, b64Encoded, username, password, CertificateResponseType.fromNumber(resulttype), doSplitLines).getEncoded();
    }
    
    public CertificateRequestResponse pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            CertificateResponseType resulttype) throws CertificateEncodingException, CertificateException, EjbcaException, CesecoreException,
            AuthorizationDeniedException, IOException, CertificateExtensionException {
        return pkcs10CertRequest(signsession, caSession, b64Encoded, username, password, resulttype, true);
    }
    
    /**
     * @deprecated Since 6.1.0, remove in 7.0.0. Use the other overloaded version taking a CertificateResponseType in the resulttype parameter.
     */
    @Deprecated
    public byte[] pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            int resulttype) throws CertificateEncodingException, CertificateException, EjbcaException, CesecoreException,
            AuthorizationDeniedException, IOException, CertificateExtensionException {
        return pkcs10CertRequest(signsession, caSession, b64Encoded, username, password, resulttype, true);
    }

    /** Handles CVC certificate requests. These are the special certificates for EAC ePassport PKI.
     * 
     * @param signsession signsession to get certificate from
     * @param b64Encoded base64 encoded cvc request message
     * @param username username of requesting user
     * @param password password of requesting user
     * @return Base64 encoded byte[] 
     * @throws Exception
     */
    public byte[] cvcCertRequest(SignSessionLocal signsession, byte[] b64Encoded, String username, String password) throws Exception {            
			CVCRequestMessage req = RequestMessageUtils.genCVCRequestMessage(b64Encoded);
    		req.setUsername(username);
            req.setPassword(password);
            // Yes it says X509ResponseMessage, but for CVC it means it just contains the binary certificate blob
            ResponseMessage resp = signsession.createCertificate(administrator, req, X509ResponseMessage.class, null);
            Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
            byte[] result = cert.getEncoded();
            log.debug("Created CV certificate for " + username);
            if (debug != null) {
                debug.print("<h4>Generated certificate:</h4>");
                debug.printInsertLineBreaks(cert.toString().getBytes());            	
            }
            return Base64.encode(result);
        } //cvcCertRequest

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
    } // ieCertFormat

   
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
        if (log.isDebugEnabled()) {
            log.debug("Response template is: "+responseTemplate);
        }
        InputStream is = sc.getResourceAsStream(responseTemplate);
        if (is == null) {
        	// Some app servers (oracle) require a / first...
            if (log.isDebugEnabled()) {
                log.debug("Trying to read responseTemplate with / first");
            }
            is = sc.getResourceAsStream("/"+responseTemplate);
        }
        if (is == null) {
        	throw new IOException("Template '(/)"+responseTemplate+"' can not be found or read.");
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

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
        if (log.isDebugEnabled()) {
            log.debug("Sent reply to IE client");
            log.debug(new String(b64cert));
        }
    } // sendNewCertToIEClient

    /**
     * Sends back cert to Firefox for installation of cert
     *
     * @param certs DER encoded certificates to be installed in browser
     * @param out output stream to send to
     *
     * @throws Exception on error
     */
    public static void sendNewCertToNSClient(byte[] certs, HttpServletResponse out)
        throws Exception {
    	log.trace(">nsCertRequest");
        if (certs.length == 0) {
            log.error("0 length certificate can not be sent to NS client!");
            return;
        }

        // Set content-type to what NS wants
        out.setContentType("application/x-x509-user-cert");
        out.setContentLength(certs.length);

        // Print the certificate
        out.getOutputStream().write(certs);
        if (log.isDebugEnabled()) {
            log.debug("Sent reply to NS client");
            log.debug(new String(Base64.encode(certs)));
        }
    	log.trace("<nsCertRequest");
    } // sendNewCertToNSClient

    /**
     * Sends back certificate as binary file (application/octet-stream)
     *
     * @param b64cert base64 encoded certificate to be returned
     * @param out output stream to send to
     * @param filename filename sent as 'Content-disposition' header 
     * @param beginKey String containing key information, i.e. BEGIN_CERTIFICATE_WITH_NL or BEGIN_PKCS7_WITH_NL
     * @param endKey String containing key information, i.e. END_CERTIFICATE_WITH_NL or END_PKCS7_WITH_NL
     * @throws IOException 
     * @throws Exception on error
     */
    public static void sendNewB64File(byte[] b64cert, HttpServletResponse out, String filename, String beginKey, String endKey) 
    throws IOException {
        if (b64cert.length == 0) {
            log.error("0 length certificate can not be sent to client!");
            return;
        }

        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(out);

        // Set content-type to general file
        out.setContentType("application/octet-stream");        
        out.setHeader("Content-disposition", "filename=\""+StringTools.stripFilename(filename)+"\"");

        out.setContentLength(b64cert.length + beginKey.length() + endKey.length());

        // Write the certificate
        ServletOutputStream os = out.getOutputStream();
        os.write(beginKey.getBytes());
        os.write(b64cert);
        os.write(endKey.getBytes());
        out.flushBuffer();
        if (log.isDebugEnabled()) {
            log.debug("Sent reply to client");
            log.debug(new String(b64cert));   
        }
    }
    /**
     * Sends back certificate as binary file (application/octet-stream)
     *
     * @param b64cert base64 encoded certificate to be returned
     * @param out output stream to send to
     * @param beginKey, String containing key information, i.e. BEGIN_CERTIFICATE_WITH_NL or BEGIN_PKCS7_WITH_NL
     * @param beginKey, String containing key information, i.e. END_CERTIFICATE_WITH_NL or END_PKCS7_WITH_NL
     * @throws Exception on error
     */
    public static void sendNewB64Cert(byte[] b64cert, HttpServletResponse out, String beginKey, String endKey)
        throws IOException {
        RequestHelper.sendNewB64File(b64cert, out, "cert.pem", beginKey, endKey);
    } // sendNewB64Cert

    /**
     * Sends back CA-certificate as binary file (application/x-x509-ca-cert)
     *
     * @param cert DER encoded certificate to be returned
     * @param out output stream to send to
     *
     * @throws Exception on error
     */
    public static void sendNewX509CaCert(byte[] cert, HttpServletResponse out)
        throws IOException {
        // Set content-type to CA-cert
        sendBinaryBytes(cert, out, "application/x-x509-ca-cert", null);
    } // sendNewX509CaCert

    /**
     * Sends back a number of bytes
     *
     * @param bytes DER encoded certificate to be returned
     * @param out output stream to send to
     * @param contentType mime type to send back bytes as
     * @param fileName to call the file in a Content-disposition, can be null to leave out this header
     *
     * @throws Exception on error
     */
    public static void sendBinaryBytes(final byte[] bytes, final HttpServletResponse out, final String contentType, final String filename)
        throws IOException {
        if ( (bytes == null) || (bytes.length == 0) ) {
            log.error("0 length can not be sent to client!");
            return;
        }

        if (filename != null) {
            // We must remove cache headers for IE
            ServletUtils.removeCacheHeaders(out);
            out.setHeader("Content-disposition", "filename=\""+StringTools.stripFilename(filename)+"\"");        	
        }

        // Set content-type to general file
        out.setContentType(contentType);
        out.setContentLength(bytes.length);

        // Write the certificate
        final ServletOutputStream os = out.getOutputStream();
        os.write(bytes);
        out.flushBuffer();
        if (log.isDebugEnabled()) {
            log.debug("Sent " + bytes.length + " bytes to client");
        }
    } // sendBinaryBytes
    
    /**
     * Sends a page with certificate information and an automatic redirect to the
     * download page. The issuer must not be a "throw away" CA.
     * 
     * @param certbytes DER encoded certificate
     * @param out output stream to send to
     * @param hidemenu whether the menu should be hidden (translates to the "hidemenu" URL parameter)
     * @param resulttype type of desired result, e.g. cert, certchain, pkcs7...
     * @throws Exception
     */
    public static void sendResultPage(byte[] certbytes, HttpServletResponse out, boolean hidemenu, CertificateResponseType resulttype) throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        String issuerDN = CertTools.getIssuerDN(cert);
        String serialNumber = CertTools.getSerialNumberAsString(cert);
        String resultTypeStr = String.valueOf(resulttype.getNumber()); 
        
        out.sendRedirect("enrol/result_download.jsp?issuer="+URLEncoder.encode(issuerDN, "UTF-8")+"&serno="+serialNumber+"&resulttype="+resultTypeStr+"&hidemenu="+hidemenu);
    }
    
    /**
     * Sends a page with certificate information and an automatic redirect to the
     * download page. The issuer must not be a "throw away" CA. The certificate
     * is automatically installed in the browser.
     * 
     * @param installToBrowser Browser type. Only "netscape" is supported,
     *                         which means "most browsers except IE".
     */
    public static void sendResultPage(byte[] certbytes, HttpServletResponse out, boolean hidemenu, String installToBrowser) throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        
        String issuerDN = CertTools.getIssuerDN(cert);
        String serialNumber = CertTools.getSerialNumberAsString(cert);
        
        out.sendRedirect("enrol/result_download.jsp?issuer="+URLEncoder.encode(issuerDN, "UTF-8")+"&serno="+serialNumber+"&installtobrowser="+installToBrowser+"&hidemenu="+hidemenu);
    }
    
    /** Sets the default character encoding for decoding post and get parameters. 
     * First tries to get the character encoding from the request, if the browser is so kind to tell us which it is using, which it never does...
     * Otherwise, when the browser is silent, it sets the character encoding to the same encoding that we use to display the pages.
     * 
     * @param request HttpServletRequest   
     * @throws UnsupportedEncodingException 
     * 
     */
    public static void setDefaultCharacterEncoding(HttpServletRequest request) throws UnsupportedEncodingException {
        String encoding = request.getCharacterEncoding();
        if(StringUtils.isEmpty(encoding)) {
            encoding = org.ejbca.config.WebConfiguration.getWebContentEncoding();
            if (log.isDebugEnabled()) {
                log.debug("Setting encoding to default value: "+encoding);
            }
            request.setCharacterEncoding(encoding);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Setting encoding to value from request: "+encoding);
            }
            request.setCharacterEncoding(encoding);         
        }        
    }

    public static String getFileNameFromCertNoEnding(Certificate cacert, String defaultname) throws NoSuchFieldException {
    	String dnpart = null;
    	if (StringUtils.equals(cacert.getType(), "CVC")) {
    		CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cacert;
    		String car = "car";
    		CAReferenceField carf = cvccert.getCVCertificate().getCertificateBody().getAuthorityReference();
    		if (carf != null) {
    			car = carf.getConcatenated();
    		}
    		String chr = "chr";
    		HolderReferenceField chrf = cvccert.getCVCertificate().getCertificateBody().getHolderReference();
    		if (chrf != null) {
    			chr = chrf.getConcatenated();
    		}
    		dnpart = car + "_" + chr;
    	} else {
    		String dn = CertTools.getSubjectDN(cacert);
    		dnpart = CertTools.getPartFromDN(dn, "CN");
    		if (dnpart == null) {
    			dnpart = CertTools.getPartFromDN(dn, "SN");
    		}
    		if (dnpart == null) {
    			dnpart = CertTools.getPartFromDN(dn, "O");
    		}
    	}
    	if (dnpart == null) {
    		dnpart = defaultname;
    	}
        if (log.isDebugEnabled()) {
            log.debug("dnpart: "+dnpart);
        }
    	// Strip whitespace though
    	String filename = dnpart.replaceAll("\\W", "");
    	return filename;
    }

}
