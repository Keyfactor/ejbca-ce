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
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.web.pub.ServletUtils;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Helper class for handling certificate request from browsers or general PKCS#10
 */
public abstract class RequestHelper {
    
    private static Logger log = Logger.getLogger(RequestHelper.class);

	public static final  String BEGIN_CERTIFICATE_REQUEST_WITH_NL = "-----BEGIN CERTIFICATE REQUEST-----\n";
	public static final  String END_CERTIFICATE_REQUEST_WITH_NL    = "\n-----END CERTIFICATE REQUEST-----\n";

    public static final  String BEGIN_CRL_WITH_NL = "-----BEGIN X509 CRL-----\n";
    public static final  String END_CRL_WITH_NL    = "\n-----END X509 CRL-----\n";

	public static final  String BEGIN_PKCS7  = "-----BEGIN PKCS7-----\n";
	public static final  String END_PKCS7     = "\n-----END PKCS7-----\n";	
	public static final  String BEGIN_PKCS7_WITH_NL = "-----BEGIN PKCS7-----\n";
	public static final  String END_PKCS7_WITH_NL    = "\n-----END PKCS7-----\n";
		
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
            if (LogRedactionUtils.redactPii()) {
                log.debug(LogRedactionUtils.REDACTED_CONTENT);
            } else {
                log.debug(new String(b64cert));
            }
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
            encoding = StandardCharsets.UTF_8.name();
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
    		dnpart = DnComponents.getPartFromDN(dn, "CN");
    		if (dnpart == null) {
    			dnpart = DnComponents.getPartFromDN(dn, "SN");
    		}
    		if (dnpart == null) {
    			dnpart = DnComponents.getPartFromDN(dn, "O");
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
