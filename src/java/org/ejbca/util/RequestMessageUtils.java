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

package org.ejbca.util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;



/**
 * Utility class to gather a few functions
 *
 * @version $Id$
 */
public class RequestMessageUtils {
	/**
	 * Determines if a de-serialized file is compatible with this class.
	 *
	 * Maintainers must change this value if and only if the new version
	 * of this class is not compatible with old versions. See Sun docs
	 * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
	 * /serialization/spec/version.doc.html> details. </a>
	 *
	 */
	static final long serialVersionUID = 3597275157018205139L;

	private static final Logger log = Logger.getLogger(RequestMessageUtils.class);

	/** Tries to parse the byte array to create a request message of the correct type.
	 * Currently handles PKCS10 request messages and CVC request messages.
	 * 
	 * @return IRequestMessage
	 */
	public static RequestMessage parseRequestMessage(byte[] request) throws IOException {
		RequestMessage ret = null;
		try {
			ret = genPKCS10RequestMessage(request);			
		} catch (IllegalArgumentException e) {
			log.debug("Can not parse PKCS10 request, trying CVC instead: "+ e.getMessage());
			ret = genCVCRequestMessage(request);
		}
		return ret;
	}

	public static ResponseMessage createResponseMessage(Class responseClass, RequestMessage req, Certificate cert, PrivateKey signPriv, String provider){
		ResponseMessage ret = null;
		// Create the response message and set all required fields
		try {
			ret = (ResponseMessage) responseClass.newInstance();
		} catch (InstantiationException e) {
			//TODO : do something with these exceptions
			log.error("Error creating response message", e);
			return null;
		} catch (IllegalAccessException e) {
			log.error("Error creating response message", e);
			return null;
		}
		if (ret.requireSignKeyInfo()) {
			ret.setSignKeyInfo(cert, signPriv, provider);
		}
		if (req.getSenderNonce() != null) {
			ret.setRecipientNonce(req.getSenderNonce());
		}
		if (req.getTransactionId() != null) {
			ret.setTransactionId(req.getTransactionId());
		}
		// Sender nonce is a random number
		byte[] senderNonce = new byte[16];
		Random randomSource = new Random();
		randomSource.nextBytes(senderNonce);
		ret.setSenderNonce(new String(Base64.encode(senderNonce)));
		// If we have a specified request key info, use it in the reply
		if (req.getRequestKeyInfo() != null) {
			ret.setRecipientKeyInfo(req.getRequestKeyInfo());
		}
		// Which digest algorithm to use to create the response, if applicable
		ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
		// Include the CA cert or not in the response, if applicable for the response type
		ret.setIncludeCACert(req.includeCACert());
		// Hint to the response which request type it is in response to
		ret.setRequestType(req.getRequestType());
		ret.setRequestId(req.getRequestId());
		// If there is some protection parameters we need to lift over from the request message, the request and response knows about it
		ret.setProtectionParamsFromRequest(req);
		return ret;
	}

	public static PKCS10RequestMessage genPKCS10RequestMessage(byte[] bytes) {
		byte[] buffer = getDecodedBytes(bytes);
		if (buffer == null) {
			return null;
		}		
		return new PKCS10RequestMessage(buffer);
	} // genPKCS10RequestMessageFromPEM

	public static CVCRequestMessage genCVCRequestMessage(byte[] bytes) { 
		byte[] buffer = getDecodedBytes(bytes);
		if (buffer == null) {
			return null;
		}		
		return new CVCRequestMessage(buffer);
	} // genCvcRequestMessageFromPEM
	
	/** Tries to get decoded, if needed, bytes from a certificate request or certificate
	 * 
	 * @param bytes pem (with headers), plain base64, or binary bytes with a CSR of certificate 
	 * @return binary bytes
	 */
	public static byte[] getDecodedBytes(byte[] bytes) {
		byte[] buffer = null;
		try {
			 buffer = getRequestBytes(bytes); 
		} catch (IOException e) {
			log.debug("Message not base64 encoded? Trying as binary: "+e.getMessage());
			buffer = bytes;
		}
		return buffer;
	}

	/** Tries to get decoded bytes from a certificate request or certificate
	 * 
	 * @param bytes pem (with headers) or plain base64 with a CSR of certificate 
	 * @return binary bytes
	 */
	public static byte[] getRequestBytes(byte[] b64Encoded) throws IOException {
		byte[] buffer = null;
		try {
			// A real PKCS10 PEM request
			String beginKey = CertTools.BEGIN_CERTIFICATE_REQUEST;
			String endKey = CertTools.END_CERTIFICATE_REQUEST;
			buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
		} catch (IOException e) {	 	
			try {
				// Keytool PKCS10 PEM request
				String beginKey = CertTools.BEGIN_KEYTOOL_CERTIFICATE_REQUEST;
				String endKey = CertTools.END_KEYTOOL_CERTIFICATE_REQUEST;
				buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
			} catch (IOException ioe) {
				try {
					// CSR can be a PEM encoded certificate instead of "certificate request"
					String beginKey = CertTools.BEGIN_CERTIFICATE;
					String endKey = CertTools.END_CERTIFICATE;
					buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
				} catch (IOException ioe2) {
					// IE PKCS10 Base64 coded request
					try {
						buffer = Base64.decode(b64Encoded);
						if (buffer == null) {
							throw new IOException("Base64 decode of buffer returns null");
						}					
					} catch (ArrayIndexOutOfBoundsException ae) {
						throw new IOException("Base64 decode fails, message not base64 encoded: "+ae.getMessage());
					}					
				}
			}
		}
		return buffer;
	}


}
