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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
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
import org.ejbca.util.HTMLTools;

/**
 * Helper class for handling certificate request from browsers or general PKCS#10
 */
public class RequestHelper {
    private static Logger log = Logger.getLogger(RequestHelper.class);
    private AuthenticationToken administrator;
    private ServletDebug debug;
    
	public static final  String BEGIN_CERTIFICATE_REQUEST_WITH_NL = "-----BEGIN CERTIFICATE REQUEST-----\n";
	public static final  String END_CERTIFICATE_REQUEST_WITH_NL    = "\n-----END CERTIFICATE REQUEST-----\n";

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
        try {
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
                    LinkedList<Certificate> chain = new LinkedList<>(caInfo.getCertificateChain());
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
        } catch (IOException e) {
            throw new CertificateEncodingException(e);
        }
    } //pkcs10CertReq
    
    /**
     * @deprecated Since 6.1.0, remove in 7.0.0. Use the other overloaded version taking a CertificateResponseType in the resulttype parameter.
     */
    @Deprecated
    public byte[] pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            int resulttype, boolean doSplitLines) throws EjbcaException, CesecoreException, AuthorizationDeniedException,
            CertificateEncodingException, CertificateException, CertificateExtensionException {
        return pkcs10CertRequest(signsession, caSession, b64Encoded, username, password, CertificateResponseType.fromNumber(resulttype), doSplitLines).getEncoded();
    }
    
    public CertificateRequestResponse pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            CertificateResponseType resulttype) throws CertificateEncodingException, CertificateException, EjbcaException, CesecoreException,
            AuthorizationDeniedException, CertificateExtensionException {
        return pkcs10CertRequest(signsession, caSession, b64Encoded, username, password, resulttype, true);
    }
    
    /**
     * @deprecated Since 6.1.0, remove in 7.0.0. Use the other overloaded version taking a CertificateResponseType in the resulttype parameter.
     */
    @Deprecated
    public byte[] pkcs10CertRequest(SignSessionLocal signsession, CaSessionLocal caSession, byte[] b64Encoded, String username, String password,
            int resulttype) throws CertificateEncodingException, CertificateException, EjbcaException, CesecoreException,
            AuthorizationDeniedException, CertificateExtensionException {
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
            if (resp.getStatus() == ResponseStatus.FAILURE) {
                final String msg = "Failed to generate CVC certificate: " + resp.getFailText();
                log.debug(msg);
                throw new EjbcaException(msg);
            }
            CardVerifiableCertificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), CardVerifiableCertificate.class);
            byte[] result = cert.getEncoded();
            log.debug("Created CV certificate for " + username);
            if (debug != null) {
                debug.print("<h4>Generated certificate:</h4>");
                debug.printInsertLineBreaks(cert.toString().getBytes());            	
            }
            return Base64.encode(result);
        } //cvcCertRequest

    /**
     * Sends back certificate as binary file (application/octet-stream)
     *
     * @param b64cert base64 encoded certificate to be returned
     * @param out output stream to send to
     * @param filename filename sent as 'Content-disposition' header 
     * @param beginKey String containing key information, i.e. BEGIN_CERTIFICATE_WITH_NL or BEGIN_PKCS7_WITH_NL
     * @param endKey String containing key information, i.e. END_CERTIFICATE_WITH_NL or END_PKCS7_WITH_NL
     * @throws IOException on error
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
        out.setHeader("Content-disposition", "attachment; filename=\""+StringTools.stripFilename(filename)+"\"");

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
     * @param beginKey String containing key information, i.e. BEGIN_CERTIFICATE_WITH_NL or BEGIN_PKCS7_WITH_NL
     * @param endKey String containing key information, i.e. END_CERTIFICATE_WITH_NL or END_PKCS7_WITH_NL
     * @throws IOException on error
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
     * @throws IOException on error
     */
    public static void sendNewX509CaCert(byte[] cert, HttpServletResponse out)
            throws IOException {
        // First we must know if this is a single cert or a CMS structure
        try {
            new CMSSignedData(cert);
            log.debug("Returning CMS with certificates as application/x-x509-ca-ra-cert");
            sendBinaryBytes(cert, out, "application/x-x509-ca-ra-cert", null);
        } catch (CMSException e) {
            // It was a cert, not a CMS
            log.debug("Returning X.509 certificate as application/x-x509-ca-cert");
            sendBinaryBytes(cert, out, "application/x-x509-ca-cert", null);
        }    
    } // sendNewX509CaCert

    /**
     * Sends back a number of bytes
     *
     * @param bytes DER encoded certificate to be returned
     * @param out output stream to send to
     * @param contentType mime type to send back bytes as
     * @param filename to call the file in a Content-disposition, can be null to leave out this header
     *
     * @throws IOException on error
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
     * Sends back a number of bytes first encoded as base64
     *
     * @param bytes Data to be encoded
     * @param out output stream to send to
     * @param contentType mime type to send back bytes as
     * @param filename to call the file in a Content-disposition, can be null to leave out this header
     *
     * @throws IOException on error
     */
    public static void sendB64BinaryBytes(final byte[] bytes, final HttpServletResponse out, final String contentType, final String filename)
    throws IOException {
        final byte[] b64bytes = Base64.encode(bytes);

        out.setHeader("Content-Transfer-Encoding", "base64");
        sendBinaryBytes(b64bytes, out, contentType, filename);
} // sendB64BinaryBytes

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

    // Uniform Resource Identifier specification has a section on parsing URIs with a regular expression. The regular expression, written by Berners-Lee, et al., is:
    // For example: http://www.ics.uci.edu/pub/ietf/uri/#Related
    // results in the following subexpression matches:
    //$1 = http:
    //$2 = http
    //$3 = //www.ics.uci.edu
    //$4 = www.ics.uci.edu
    //$5 = /pub/ietf/uri/
    //$6 = <undefined>
    //$7 = <undefined>
    //$8 = #Related
    //$9 = Related
    // Port is part of the name in $4
    // See https://stackoverflow.com/questions/27745/getting-parts-of-a-url-regex
    private static java.util.regex.Pattern reg = java.util.regex.Pattern.compile("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");
    /**
     * Method that returns the servername including port, extracted from the HTTPServlet Request, no protocol or application path is returned
     *
     * @return the server name and port requested, i.e. localhost:8443
     */
    public static String getRequestServerName(final String request) {
        if (request == null) {
            return null;
        }
        final java.util.regex.Matcher m = reg.matcher(request);
        String requestURL = null;
        if (m.matches() && m.groupCount() >= 4) {
            if (log.isTraceEnabled()) {
                log.trace("regexp match with "+m.groupCount()+" groups, 0 being: "+m.group(0));
            }
            requestURL = m.group(4);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("no reqexp match: "+request);
            }
            // Remove https://
            requestURL = request.substring(8);
            int firstSlash = requestURL.indexOf("/");
            // Remove application path
            requestURL = requestURL.substring(0, firstSlash);            
        }        
        // Escape in order to be sure not to have any XSS
        requestURL = HTMLTools.htmlescape(requestURL);
        if (log.isDebugEnabled()) {
            log.debug("requestServerName: " + requestURL);
        }
        return requestURL;
    }

}
