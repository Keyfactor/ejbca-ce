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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Utility class to gather a few functions
 *
 * @version $Id$
 */
public abstract class RequestMessageUtils {
	
	private static final Logger log = Logger.getLogger(RequestMessageUtils.class);

	/** Tries to parse the byte array to create a request message of the correct type.
	 * Currently handles PKCS10 request messages and CVC request messages.
	 * 
	 * @return IRequestMessage
	 */
	public static RequestMessage parseRequestMessage(byte[] request) {
		RequestMessage ret = null;
		try {
			ret = genPKCS10RequestMessage(request);			
		} catch (IllegalArgumentException e) {
			log.debug("Can not parse PKCS10 request, trying CVC instead: "+ e.getMessage());
			ret = genCVCRequestMessage(request);
		}
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
					} catch (DecoderException de) {
						throw new IOException("Base64 decode fails, message not base64 encoded: "+de.getMessage());
					}					
				}
			}
		}
		return buffer;
	}

    public static RequestMessage getRequestMessageFromType(final String username, final String password, final String req, final int reqType)
            throws SignRequestSignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException,
            SignatureException, InvalidKeySpecException, ParseException, ConstructionException, NoSuchFieldException {
	    RequestMessage ret = null;
        if (reqType == CertificateConstants.CERT_REQ_TYPE_PKCS10) {
            final PKCS10RequestMessage pkcs10RequestMessage = RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
            pkcs10RequestMessage.setUsername(username);
            pkcs10RequestMessage.setPassword(password);
            ret = pkcs10RequestMessage;
        } else if (reqType == CertificateConstants.CERT_REQ_TYPE_SPKAC) {
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
        } else if (reqType == CertificateConstants.CERT_REQ_TYPE_CRMF) {
            final byte[] certificateRequestMessages = Base64.decode(req.getBytes());
            final CertReqMsg certReqMsg = CertReqMsg.getInstance(((ASN1Sequence)ASN1Sequence.fromByteArray(certificateRequestMessages)).getObjectAt(0));
            final JcaCertificateRequestMessage jcrm = new JcaCertificateRequestMessage(certReqMsg);
            try {
                final PublicKey publicKey = jcrm.getPublicKey();
                if (jcrm.hasProofOfPossession()) {
                    switch (jcrm.getProofOfPossessionType()) {
                    case JcaCertificateRequestMessage.popRaVerified: {
                        // The requestor claims that it is verified by an RA
                        break;
                    }
                    case JcaCertificateRequestMessage.popSigningKey: {
                        // RFC 4211 Section 4.1
                        final POPOSigningKey popoSigningKey = POPOSigningKey.getInstance(jcrm.toASN1Structure().getPopo().getObject());
                        if (log.isDebugEnabled()) {
                            if (popoSigningKey!=null) {
                                log.debug("CRMF POPOSigningKey poposkInput:                      " + popoSigningKey.getPoposkInput());
                                if (popoSigningKey.getPoposkInput()!=null) {
                                    log.debug("CRMF POPOSigningKey poposkInput PublicKey:            " + popoSigningKey.getPoposkInput().getPublicKey());
                                    log.debug("CRMF POPOSigningKey poposkInput PublicKeyMAC:         " + popoSigningKey.getPoposkInput().getPublicKeyMAC());
                                }
                                log.debug("CRMF POPOSigningKey algorithmIdentifier.algorithm.id: " + popoSigningKey.getAlgorithmIdentifier().getAlgorithm().getId());
                                log.debug("CRMF POPOSigningKey signature:                        " + popoSigningKey.getSignature());
                            } else {
                                log.debug("CRMF POPOSigningKey is not defined even though POP type is popSigningKey. Validation will fail.");
                            }
                        }
                        final ContentVerifierProvider cvp = CertTools.genContentVerifierProvider(publicKey);
                        // Work around for bug in BC where jcrm.hasSigningKeyProofOfPossessionWithPKMAC() will throw NPE if PoposkInput is null
                        if (popoSigningKey.getPoposkInput()!=null && jcrm.hasSigningKeyProofOfPossessionWithPKMAC()) {
                            final PKMACBuilder pkmacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BouncyCastleProvider.PROVIDER_NAME));
                            if (!jcrm.isValidSigningKeyPOP(cvp, pkmacBuilder, password.toCharArray())) {
                                throw new SignRequestSignatureException("CRMF POP with PKMAC failed signature or MAC validation.");
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("CRMF POP with PKMAC passed signature and PKMAC validation.");
                                }
                            }
                        } else {
                            if (!jcrm.isValidSigningKeyPOP(cvp)) {
                                throw new SignRequestSignatureException("CRMF POP failed signature validation.");
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("CRMF POP passed signature validation.");
                                }
                            }
                        }
                        break;
                    }
                    case JcaCertificateRequestMessage.popKeyEncipherment: {
                        // RFC 4211 Section 4.2 (Not implemented)
                        log.info("CRMF RFC4211 Section 4.2 KeyEncipherment POP validation is not implemented. Will try to use the request's public key anyway.");
                        break;
                    }
                    case JcaCertificateRequestMessage.popKeyAgreement: {
                        // RFC 4211 Section 4.3 (Not implemented)
                        log.info("CRMF RFC4211 Section 4.3 KeyAgreement POP validation is not implemented. Will try to use the request's public key anyway.");
                        break;
                    }
                    default:
                        throw new SignRequestSignatureException("CRMF POP of type "+jcrm.getProofOfPossessionType()+" is unknown.");
                    }
                }
                final SimpleRequestMessage simpleRequestMessage = new SimpleRequestMessage(publicKey, username, password);
                simpleRequestMessage.setRequestExtensions(jcrm.getCertTemplate().getExtensions());
                ret = simpleRequestMessage;
            } catch (CRMFException e) {
                throw new SignRequestSignatureException("CRMF POP verification failed.", e);
            } catch (OperatorCreationException e) {
                throw new SignRequestSignatureException("CRMF POP verification failed.", e);
            }
        } else if (reqType == CertificateConstants.CERT_REQ_TYPE_PUBLICKEY) {
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
                } catch (DecoderException de) {
                    throw new IOException("Base64 decode fails, message not base64 encoded: " + de.getMessage());
                }
            }
            final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(request);
            ret = new SimpleRequestMessage(pubKey, username, password);
        } else if (reqType == CertificateConstants.CERT_REQ_TYPE_CVC) {
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
