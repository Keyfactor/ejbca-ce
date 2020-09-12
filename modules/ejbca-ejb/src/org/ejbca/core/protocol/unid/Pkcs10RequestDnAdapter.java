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

package org.ejbca.core.protocol.unid;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.CertTools;

/**
 * Holder for a modified Pkcs10RequestMessage
 */
public class Pkcs10RequestDnAdapter implements RequestMessage {
  

    private static final long serialVersionUID = 1L;
    private final PKCS10RequestMessage original;
	private transient X500Name dn;

	public Pkcs10RequestDnAdapter(RequestMessage req, X500Name _dn) {
        this.original = (PKCS10RequestMessage) req;
		this.dn = _dn;
	}
    @Override
    public String getCASequence() {
        return null;
    }
	@Override
	public String getUsername() {
		return this.original.getUsername();
	}
	@Override
	public String getPassword() {
		return this.original.getPassword();
	}
	@Override
	public String getIssuerDN() {
		return this.original.getIssuerDN();
	}
	@Override
	public BigInteger getSerialNo() {
		return this.original.getSerialNo();
	}
	@Override
	public String getRequestDN() {
		final X500Name name = getRequestX500Name();
		if ( name==null ) {
			return null;
		}
		return CertTools.stringToBCDNString(name.toString());
	}
	@Override
	public X500Name getRequestX500Name() {
	    return this.dn;
	}
	@Override
	public String getRequestAltNames() {
		return this.original.getRequestAltNames();
	}
	@Override
	public Date getRequestValidityNotBefore() {
		return this.original.getRequestValidityNotBefore();
	}
	@Override
	public Date getRequestValidityNotAfter() {
		return this.original.getRequestValidityNotAfter();
	}
	@Override
	public Extensions getRequestExtensions() {
		return this.original.getRequestExtensions();
	}
	@Override
	public String getCRLIssuerDN() {
		return this.original.getCRLIssuerDN();
	}
	@Override
	public BigInteger getCRLSerialNo() {
		return this.original.getCRLSerialNo();
	}
	@Override
	public PublicKey getRequestPublicKey() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return this.original.getRequestPublicKey();
	}
	@Override
	public boolean verify() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return this.original.verify();
	}
	@Override
	public boolean requireKeyInfo() {
		return this.original.requireKeyInfo();
	}
	@Override
	public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
		this.original.setKeyInfo(cert, key, provider);
	}
	@Override
	public int getErrorNo() {
		return this.original.getErrorNo();
	}
	@Override
	public String getErrorText() {
		return this.original.getErrorText();
	}
	@Override
	public String getSenderNonce() {
		return this.original.getSenderNonce();
	}
	@Override
	public String getTransactionId() {
		return this.original.getTransactionId();
	}
	@Override
	public byte[] getRequestKeyInfo() {
		return this.original.getRequestKeyInfo();
	}
	@Override
	public String getPreferredDigestAlg() {
		return this.original.getPreferredDigestAlg();
	}
	@Override
	public boolean includeCACert() {
		return this.original.includeCACert();
	}
	@Override
	public int getRequestType() {
		return this.original.getRequestType();
	}
	@Override
	public int getRequestId() {
		return this.original.getRequestId();
	}
	
    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
        this.original.setResponseKeyInfo(key, provider);
    }
    
    @Override
    public List<Certificate> getAdditionalCaCertificates() {
        return this.original.getAdditionalCaCertificates();
    }
    @Override
    public void setAdditionalCaCertificates(final List<Certificate> certificates) {
        this.original.setAdditionalCaCertificates(certificates);
    }
    @Override
    public List<Certificate> getAdditionalExtraCertsCertificates() {
        return original.getAdditionalExtraCertsCertificates();
    }
    @Override
    public void setAdditionalExtraCertsCertificates(List<Certificate> certificates) {
        this.original.setAdditionalExtraCertsCertificates(certificates);
    }
    @Override
    public void setUsername(String username) {
        this.original.setUsername(username);
    }
    @Override
    public void setPassword(String pwd) {
        this.original.setPassword(pwd);
        
    }
    @Override
    public void setRequestValidityNotAfter(Date notAfter) {
        this.original.setRequestValidityNotAfter(notAfter);
    }
}
