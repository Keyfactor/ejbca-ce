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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedGenerator;



/**
 * Class to handle simple requests from only a public key, all required parameters must be set.
 *
 * Based on EJBCA version: SimpleRequestMessage.java 10364 2010-11-04 09:57:19Z anatom
 * 
 * @version $Id$
 */
public class SimpleRequestMessage implements RequestMessage {
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

    /** The public key */
    protected PublicKey pubkey;

    /** manually set password */
    protected String password = null;

    /** manually set username */
    protected String username = null;
    
    /** If the CA certificate should be included in the response or not, default to true = yes */
    protected boolean includeCACert = true;

    /** preferred digest algorithm to use in replies, if applicable */
    private transient String preferredDigestAlg = CMSSignedGenerator.DIGEST_SHA1;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    /** Issue DN, if set manually */
    private String issuerDN = null;
    
    /** request X509Name, if set manually */
    private String requestDN = null;

    /** Requested certificate extensions */
    private X509Extensions x509Extensions = null;
    
    /**
     * Constructs a new Simple message handler object.
     * @param pubkey the public key to be certified
     * @param username username of the EJBCA user
     * @param password password of the EJBCA user
     * @param extensions requested certificate extensions, or null
     */
    public SimpleRequestMessage(final PublicKey pubkey, final String username, final String password) {
        this.pubkey = pubkey;
        this.username = username;
        this.password = password;
    }

    /**
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    	return pubkey;
    }

    /** set a password
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    /**
     * @return password.
     */
    public String getPassword() {
    	return password;
    }

    /** set a username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return username, which is the CN field from the subject DN in certification request.
     */
    public String getUsername() {
    	return username;
    }

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /** Sets the issuer DN manually, since it can not be contained in the request for
     * this type of simple request message 
     * @param dn issuerDN, in CertTools.stringToBCDnString() format
     */
    public void setIssuerDN(String dn) {
    	this.issuerDN = dn;
    }
    /**
     * Gets the number (of CA cert) from IssuerAndSerialNumber. Combined with getIssuerDN to identify
     * the CA-certificate of the CA the request is targeted for.
     *
     * @return serial number of CA certificate for CA issuing CRL or null.
     */
    public BigInteger getSerialNo() {
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
    	return null;
    }

    /**
     * @see RequestMessage#getRequestX509Name()
     */
    public X509Name getRequestX509Name() {
    	if (this.requestDN == null) {
    		return null;
    	}
    	return new X509Name(this.requestDN);
    }

    public void setRequestDN(String dn) {
    	this.requestDN = dn;
    }
    
    public String getRequestAltNames() {
    	return null;
    }

    /**
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     */
	public Date getRequestValidityNotBefore() {
		return null;
	}
	
    /**
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     */
	public Date getRequestValidityNotAfter() {
		return null;
	}
	
    /**
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     */
	public X509Extensions getRequestExtensions() {
	    return x509Extensions;
	}
	
	/** Sets request extensions, if any */
	public void setRequestExtensions(final X509Extensions extensions) {
	    this.x509Extensions = extensions;
	}
	
    /**
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public boolean verify()
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return true;
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
     * Returns an error number after an error has occured processing the request
     *
     * @return class specific error number
     */
    public int getErrorNo() {
        return error;
    }

    /**
     * Returns an error message after an error has occured processing the request
     *
     * @return class specific error message
     */
    public String getErrorText() {
        return errorText;
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
        return null;
    }
    
    /** @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public String getPreferredDigestAlg() {
    	return preferredDigestAlg;
    }
    /** @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public boolean includeCACert() {
    	return includeCACert;
    }

    /** @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public int getRequestType() {
    	return 0;
    }
    
    /** @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public int getRequestId() {
    	return 0;
    }
    
    /** @see org.cesecore.certificates.certificate.request.RequestMessage
     */
    public CertificateResponseMessage createResponseMessage(Class responseClass, RequestMessage req, Certificate cert, PrivateKey signPriv, String provider) {
    	return RequestMessageUtils.createResponseMessage(responseClass, req, cert, signPriv, provider);
    }
} // SimpleRequestMessage
