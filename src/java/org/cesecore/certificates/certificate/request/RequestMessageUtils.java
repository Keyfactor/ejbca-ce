/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.request;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import com.novosec.pkix.asn1.crmf.CertRequest;


/**
 * Utility class to gather a few functions
 *
 * Based on EJBCA version: RequestMessageUtils.java 10878 2010-12-15 13:23:52Z anatom
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

	public static CertificateResponseMessage createResponseMessage(Class<? extends ResponseMessage> responseClass, RequestMessage req, Certificate cert, PrivateKey signPriv, String provider){
	    CertificateResponseMessage ret = null;
		// Create the response message and set all required fields
		try {
			ret = (CertificateResponseMessage) responseClass.newInstance();
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

	public static RequestMessage getSimpleRequestMessageFromType(final String username, final String password, final String req, final int reqType) throws SignRequestSignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException, InvalidKeySpecException, ParseException, ConstructionException, NoSuchFieldException {
	    RequestMessage ret = null;
        if (reqType == SecConst.CERT_REQ_TYPE_PKCS10) {
            final RequestMessage pkcs10req = RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
            final PublicKey pubKey = pkcs10req.getRequestPublicKey();
            SimpleRequestMessage simplereq = new SimpleRequestMessage(pubKey, username, password);
            final X509Extensions ext = pkcs10req.getRequestExtensions();
            simplereq.setRequestExtensions(ext);
            ret = simplereq;
        } else if (reqType == SecConst.CERT_REQ_TYPE_SPKAC) {
            byte[] reqBytes = req.getBytes();
            if (reqBytes != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Received NS request: "+new String(reqBytes));
                }
                byte[] buffer = Base64.decode(reqBytes);
                if (buffer == null) {
                    return null;
                }
                ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(buffer));
                ASN1Sequence spkacSeq = (ASN1Sequence) in.readObject();
                in.close();
                NetscapeCertRequest nscr = new NetscapeCertRequest(spkacSeq);
                // Verify POPO, we don't care about the challenge, it's not important.
                nscr.setChallenge("challenge");
                if (nscr.verify("challenge") == false) {
                    if (log.isDebugEnabled()) {
                        log.debug("SPKAC POPO verification Failed");
                    }
                    throw new SignRequestSignatureException("Invalid signature in NetscapeCertRequest, popo-verification failed.");
                }
                if (log.isDebugEnabled()) {
                    log.debug("POPO verification successful");
                }
                PublicKey pubKey = nscr.getPublicKey();
                ret = new SimpleRequestMessage(pubKey, username, password);
            }       
        } else if (reqType == SecConst.CERT_REQ_TYPE_CRMF) {
            byte[] request = Base64.decode(req.getBytes());
            ASN1InputStream in = new ASN1InputStream(request);
            ASN1Sequence    crmfSeq = (ASN1Sequence) in.readObject();
            ASN1Sequence reqSeq =  (ASN1Sequence) ((ASN1Sequence) crmfSeq.getObjectAt(0)).getObjectAt(0);
            CertRequest certReq = new CertRequest( reqSeq );
            SubjectPublicKeyInfo pKeyInfo = certReq.getCertTemplate().getPublicKey();
            KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
            KeySpec keySpec = new X509EncodedKeySpec( pKeyInfo.getEncoded() );
            PublicKey pubKey = keyFact.generatePublic(keySpec); // just check it's ok
            SimpleRequestMessage simplereq = new SimpleRequestMessage(pubKey, username, password);
            X509Extensions ext = certReq.getCertTemplate().getExtensions();
            simplereq.setRequestExtensions(ext);
            ret = simplereq;
            // a simple crmf is not a complete PKI message, as desired by the CrmfRequestMessage class
            //PKIMessage msg = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(request)).readObject());
            //CrmfRequestMessage reqmsg = new CrmfRequestMessage(msg, null, true, null);
            //imsg = reqmsg;
        } else if (reqType == SecConst.CERT_REQ_TYPE_PUBLICKEY) {
            byte[] request;
            // Request can be Base64 encoded or in PEM format
            try {
                request = FileTools.getBytesFromPEM(req.getBytes(), CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
            } catch (IOException ex) {
                try {
                    request = Base64.decode(req.getBytes());
                    if (request == null) {
                        throw new IOException("Base64 decode of buffer returns null");
                    }
                } catch (ArrayIndexOutOfBoundsException ae) {
                    throw new IOException("Base64 decode fails, message not base64 encoded: " + ae.getMessage());
                }
            }
            final ASN1InputStream in = new ASN1InputStream(request);
            final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(in.readObject());
            final AlgorithmIdentifier keyAlg = keyInfo.getAlgorithmId();
            final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(keyInfo).getBytes());
            final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getObjectId().getId(), "BC");
            final PublicKey pubKey = keyFact.generatePublic(xKeySpec);
            ret = new SimpleRequestMessage(pubKey, username, password);
        } else if (reqType == SecConst.CERT_REQ_TYPE_CVC) {
            CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(req.getBytes()));
            // We will handle both the case if the request is an authenticated request, i.e. with an outer signature
            // and when the request is missing the (optional) outer signature.
            CVCertificate cvccert = null;
            if (parsedObject instanceof CVCAuthenticatedRequest) {
                CVCAuthenticatedRequest cvcreq = (CVCAuthenticatedRequest)parsedObject;
                cvccert = cvcreq.getRequest();
            } else {
                cvccert = (CVCertificate)parsedObject;
            }
            CVCRequestMessage reqmsg = new CVCRequestMessage(cvccert.getDEREncoded());
            reqmsg.setUsername(username);
            reqmsg.setPassword(password);
            // Popo is really actually verified by the CA (in SignSessionBean) as well
            if (reqmsg.verify() == false) {
                if (log.isDebugEnabled()) {
                    log.debug("CVC POPO verification Failed");
                }
                throw new SignRequestSignatureException("Invalid inner signature in CVCRequest, popo-verification failed.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("POPO verification successful");
                }
            }
            ret = reqmsg;
        }
        return ret;
	}

}
