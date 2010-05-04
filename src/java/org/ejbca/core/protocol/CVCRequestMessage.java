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

package org.ejbca.core.protocol;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;



/**
 * Class to handle CVC request messages sent to the CA.
 *
 * @version $Id$
 */
public class CVCRequestMessage implements IRequestMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(CVCRequestMessage.class);

    /** Raw form of the CVC message */
    protected byte[] cvcmsg;

    /** manually set password */
    protected String password = null;

    /** manually set username */
    protected String username = null;
    
    /** The cvc request message, not serialized. */
    protected transient CVCertificate cvcert = null;

    /**
     * Constructs a new empty message handler object.
     */
    public CVCRequestMessage() {
    	// No constructor
    }

    /**
     * Constructs a new message handler object.
     *
     * @param msg The DER encoded request.
     */
    public CVCRequestMessage(byte[] msg) {
        this.cvcmsg = msg;
        init();
    }

    private void init() {
		try {
			CVCObject parsedObject;
			parsedObject = CertificateParser.parseCVCObject(cvcmsg);
			if (parsedObject instanceof CVCertificate) {
				cvcert = (CVCertificate) parsedObject;
			} else if (parsedObject instanceof CVCAuthenticatedRequest) {
				CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
				cvcert = authreq.getRequest();
			}
		} catch (ParseException e) {
            log.error("Error in init for CVC request: ", e);
            throw new IllegalArgumentException(e);
		} catch (ConstructionException e) {
            log.error("Error in init for CVC request: ", e);
            throw new IllegalArgumentException(e);
		} catch (NoSuchFieldException e) {
            log.error("Error in init for CVC request: ", e);
            throw new IllegalArgumentException(e);
		}
    }

    public PublicKey getRequestPublicKey()
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    	try {
    		if (cvcert == null) {
    			init();
    		}
        } catch (IllegalArgumentException e) {
            log.error("CVC not inited!");
            return null;
        }

        PublicKey pk;
		try {
			pk = cvcert.getCertificateBody().getPublicKey();
		} catch (NoSuchFieldException e) {
			throw new InvalidKeyException(e);
		}
        return pk;
    }

    /** force a password
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    /**
     * Returns the forced password
     *
     * @return password
     */
    public String getPassword() {
    	return password;
    }

    /** force a username, i.e. ignore the DN/username in the request
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the string representation of the holderReference field (mnemonic+country) of the certification request,
     * to be used as username.
     *
     * @return username, which is the holderReference field from the subject DN in certification request.
     */
    public String getUsername() {
        if (username != null) {
            return username;
        }
        String subject = null;
		try {
			HolderReferenceField hr = cvcert.getCertificateBody().getHolderReference();
			subject = hr.getMnemonic()+hr.getCountry();
		} catch (NoSuchFieldException e) {
			log.error(e);
		}
        return subject;
    }

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    public String getIssuerDN() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getIssuerDN(cc);
    }

    /**
     * Could get the sequence (of CVC cert). For CVC certificate this does not combine well with getIssuerDN to identify
     * the CA-certificate of the CA the request is targeted for, so it always return null.
     *
     * @return null.
     */
    public BigInteger getSerialNo() {
    	//CardVerifiableCertificate cc = getCardVerifiableCertificate()
        //return CertTools.getSerialNumber(cc);
    	return null;
    }
    
    /**
     * Gets the issuer DN (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return issuerDN of CA issuing CRL.
     */
    public String getCRLIssuerDN() {
        return null;
    }

    /**
     * Gets the number (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return serial number of CA certificate for CA issuing CRL.
     */
    public BigInteger getCRLSerialNo() {
        return null;
    }

    /**
     * Returns the string representation of the subject DN from the certification request.
     *
     * @return subject DN from certification request or null.
     */
    public String getRequestDN() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getSubjectDN(cc);
    }

    /**
     * @see IRequestMessage#getRequestX509Name()
     */
    public X509Name getRequestX509Name() {
    	String dn = getRequestDN();
    	X509Name name = new X509Name(dn);
    	return name;
    }

    public String getRequestAltNames() {
    	return null;
    }

    /**
     * @see org.ejbca.core.protocol.IRequestMessage
     */
	public Date getRequestValidityNotBefore() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getNotBefore(cc);
	}
	
    /**
     * @see org.ejbca.core.protocol.IRequestMessage
     */
	public Date getRequestValidityNotAfter() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getNotAfter(cc);
	}
	
    /**
     * @see org.ejbca.core.protocol.IRequestMessage
     */
	public X509Extensions getRequestExtensions() {
		return null;
	}
	
    /**
     * @see org.ejbca.core.protocol.IRequestMessage
     */
    public boolean verify()
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return verify(null);
    }
    private boolean verify(PublicKey pubKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        log.trace(">verify()");

        boolean ret = false;

        try {
        	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        	if (cc != null) {
                if (pubKey == null) {
                	cc.verify(cvcert.getCertificateBody().getPublicKey());
                	ret = true; // If we came here verification was successful
                } else {
                    cc.verify(pubKey);
                	ret = true; // If we came here verification was successful
                }        		
        	}
        } catch (NoSuchFieldException e) {
            log.error("CVC error!", e);
        } catch (InvalidKeyException e) {
            log.error("Error in CVC-request:", e);
            throw e;
        } catch (CertificateException e) {
            log.error("Error in CVC-signature:", e);
        } catch (SignatureException e) {
            log.error("Error in CVC-signature:", e);
        }

        log.trace("<verify()");

        return ret;
    }

    /**
     * indicates if this message needs recipients public and private key to verify, decrypt etc. If
     * this returns true, setKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireKeyInfo() {
        return false;
    }

    /**
     * Sets the public and private key needed to decrypt/verify the message. Must be set if
     * requireKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireKeyInfo()
     */
    public void setKeyInfo(Certificate cert, PrivateKey key, String Provider) {
    }

    /**
     * Returns an error number after an error has occurred processing the request
     *
     * @return class specific error number
     */
    public int getErrorNo() {
        return 0;
    }

    /**
     * Returns an error message after an error has occurred processing the request
     *
     * @return class specific error message
     */
    public String getErrorText() {
        return "";
    }

    /**
     * Returns a senderNonce if present in the request
     *
     * @return senderNonce
     */
    public String getSenderNonce() {
        return null;
    }

    /**
     * Returns a transaction identifier if present in the request
     *
     * @return transaction id
     */
    public String getTransactionId() {
        return null;
    }

    /**
     * Returns requesters key info, key id or similar
     *
     * @return request key info
     */
    public byte[] getRequestKeyInfo() {
    	byte[] ret = null;
    	try {
        	String seq = cvcert.getCertificateBody().getHolderReference().getSequence();
        	ret = seq.getBytes();
    	} catch (NoSuchFieldException e) {
            log.error("CVC error!", e);
    	}
        return ret;
    }
    
    /** @see org.ejbca.core.protocol.IRequestMessage
     */
    public String getPreferredDigestAlg() {
    	// Not used
    	return CMSSignedGenerator.DIGEST_SHA256;
    }
    /** @see org.ejbca.core.protocol.IRequestMessage
     */
    public boolean includeCACert() {
    	return false;
    }

    /** @see org.ejbca.core.protocol.IRequestMessage
     */
    public int getRequestType() {
    	return 0;
    }
    
    /** @see org.ejbca.core.protocol.IRequestMessage
     */
    public int getRequestId() {
    	return 0;
    }
    
    /** @see org.ejbca.core.protocol.IRequestMessage
     */
    public IResponseMessage createResponseMessage(Class responseClass, IRequestMessage req, Certificate cert, PrivateKey signPriv, PrivateKey encPriv, String provider) {
    	return RequestMessageUtils.createResponseMessage(responseClass, req, cert, signPriv, encPriv, provider);
    }
    
    /** Specific to CVC request messages, EAC requests contains a sequence */
    public String getKeySequence() {
    	String ret = null;
    	try {
			if (cvcert.getCertificateBody().getHolderReference() != null) {
				ret = cvcert.getCertificateBody().getHolderReference().getSequence();    		
			}
		} catch (NoSuchFieldException e) {
			// No sequence found...
		}
    	return ret;
    }
    
    private CardVerifiableCertificate getCardVerifiableCertificate() {
    	try {
    		if (cvcert == null) {
    			init();
    		}
        } catch (IllegalArgumentException e) {
            log.error("CVC not inited!", e);
            return null;
        }
    	CardVerifiableCertificate cc = new CardVerifiableCertificate(cvcert);
    	return cc;
    }
} // PKCS10RequestMessage
