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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CeSecoreNameStyle;



/**
 * Class to handle simple requests from only a public key, all required parameters must be set.
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
    
    /** request X500Name, if set manually */
    private String requestDN = null;

    /** Requested certificate extensions */
    private Extensions x509Extensions = null;
    
    /** Private key used for signing/encrypting response, if needed */
    private PrivateKey responsePrivateKey;
    /** Security provider used for the responsePrivateKey */
    private String responseProvider = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * Constructs a new Simple message handler object.
     * @param pubkey the public key to be certified
     * @param username username of the EJBCA user
     * @param password password of the EJBCA user
     */
    public SimpleRequestMessage(final PublicKey pubkey, final String username, final String password) {
        this.pubkey = pubkey;
        this.username = username;
        this.password = password;
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    	return pubkey;
    }

    /** set a password
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    @Override
    public String getPassword() {
    	return password;
    }

    /** set a username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getUsername() {
    	return username;
    }

    @Override
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
    @Override
    public BigInteger getSerialNo() {
    	return null;
    }
    
    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    @Override
    public String getRequestDN() {
    	return null;
    }

    @Override
    public X500Name getRequestX500Name() {
    	if (this.requestDN == null) {
    		return null;
    	}
    	return new X500Name(new CeSecoreNameStyle(), this.requestDN);
    }

    public void setRequestDN(String dn) {
    	this.requestDN = dn;
    }
    
    @Override
    public String getRequestAltNames() {
    	return null;
    }

    @Override
	public Date getRequestValidityNotBefore() {
		return null;
	}
	
    @Override
	public Date getRequestValidityNotAfter() {
		return null;
	}
	
    @Override
	public Extensions getRequestExtensions() {
	    return x509Extensions;
	}
	
	/** Sets request extensions, if any */
	public void setRequestExtensions(final Extensions extensions) {
	    this.x509Extensions = extensions;
	}
	
    @Override
    public boolean verify()
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return true;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String Provider) {
    }

    @Override
    public int getErrorNo() {
        return error;
    }

    @Override
    public String getErrorText() {
        return errorText;
    }

    @Override
    public String getSenderNonce() {
        return null;
    }

    @Override
    public String getTransactionId() {
        return null;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return null;
    }
    
    @Override
    public String getPreferredDigestAlg() {
    	return preferredDigestAlg;
    }
    @Override
    public boolean includeCACert() {
    	return includeCACert;
    }

    @Override
    public int getRequestType() {
    	return 0;
    }
    
    @Override
    public int getRequestId() {
    	return 0;
    }

    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
        this.responsePrivateKey = key;
        if (provider != null) {
            this.responseProvider = provider;
        }
    }

} // SimpleRequestMessage
