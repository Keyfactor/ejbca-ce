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

package org.ejbca.util.unid;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import org.bouncycastle.jce.X509Principal;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.CertTools;



/**
 * Changes the DN in an IRequestMessage
 * @author primelars
 * @version $Id$
 *
 */
class RequestMessageSubjectDnAdapter implements IRequestMessage {
	final private IRequestMessage original;
	transient private X509Principal dn;

	private void writeObject(ObjectOutputStream stream) throws IOException {
		stream.defaultWriteObject();
		stream.writeObject( this.dn.getEncoded() );
	}
	private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
		stream.defaultReadObject();
		final byte b[] = (byte[])stream.readObject();
		this.dn = new X509Principal(b);
	}
	RequestMessageSubjectDnAdapter(IRequestMessage req, X509Name _dn) {
		this.original = req;
		this.dn = new X509Principal(_dn);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getUsername()
	 */
	@Override
	public String getUsername() {
		return this.original.getUsername();
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getPassword()
	 */
	@Override
	public String getPassword() {
		return this.original.getPassword();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getIssuerDN()
	 */
	@Override
	public String getIssuerDN() {
		return this.original.getIssuerDN();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getSerialNo()
	 */
	@Override
	public BigInteger getSerialNo() {
		return this.original.getSerialNo();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestDN()
	 */
	@Override
	public String getRequestDN() {
		final X509Name name = getRequestX509Name();
		if ( name==null ) {
			return null;
		}
		return CertTools.stringToBCDNString(name.toString());
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestX509Name()
	 */
	@Override
	public X509Name getRequestX509Name() {
		return this.dn;
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestAltNames()
	 */
	@Override
	public String getRequestAltNames() {
		return this.original.getRequestAltNames();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestValidityNotBefore()
	 */
	@Override
	public Date getRequestValidityNotBefore() {
		return this.original.getRequestValidityNotBefore();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestValidityNotAfter()
	 */
	@Override
	public Date getRequestValidityNotAfter() {
		return this.original.getRequestValidityNotAfter();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestExtensions()
	 */
	@Override
	public X509Extensions getRequestExtensions() {
		return this.original.getRequestExtensions();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getCRLIssuerDN()
	 */
	@Override
	public String getCRLIssuerDN() {
		return this.original.getCRLIssuerDN();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getCRLSerialNo()
	 */
	@Override
	public BigInteger getCRLSerialNo() {
		return this.original.getCRLSerialNo();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestPublicKey()
	 */
	@Override
	public PublicKey getRequestPublicKey() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return this.original.getRequestPublicKey();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#verify()
	 */
	@Override
	public boolean verify() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return this.original.verify();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#requireKeyInfo()
	 */
	@Override
	public boolean requireKeyInfo() {
		return this.original.requireKeyInfo();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#setKeyInfo(java.security.cert.Certificate, java.security.PrivateKey, java.lang.String)
	 */
	@Override
	public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
		this.original.setKeyInfo(cert, key, provider);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getErrorNo()
	 */
	@Override
	public int getErrorNo() {
		return this.original.getErrorNo();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getErrorText()
	 */
	@Override
	public String getErrorText() {
		return this.original.getErrorText();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getSenderNonce()
	 */
	@Override
	public String getSenderNonce() {
		return this.original.getSenderNonce();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getTransactionId()
	 */
	@Override
	public String getTransactionId() {
		return this.original.getTransactionId();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestKeyInfo()
	 */
	@Override
	public byte[] getRequestKeyInfo() {
		return this.original.getRequestKeyInfo();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getPreferredDigestAlg()
	 */
	@Override
	public String getPreferredDigestAlg() {
		return this.original.getPreferredDigestAlg();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#includeCACert()
	 */
	@Override
	public boolean includeCACert() {
		return this.original.includeCACert();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestType()
	 */
	@Override
	public int getRequestType() {
		return this.original.getRequestType();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#getRequestId()
	 */
	@Override
	public int getRequestId() {
		return this.original.getRequestId();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.IRequestMessage#createResponseMessage(java.lang.Class, org.ejbca.core.protocol.IRequestMessage, java.security.cert.Certificate, java.security.PrivateKey, java.lang.String)
	 */
	@Override
	public IResponseMessage createResponseMessage(Class responseClass,
			IRequestMessage req, Certificate cert, PrivateKey signPriv,
			String provider) {
		return this.original.createResponseMessage(responseClass, req, cert, signPriv, provider);
	}		
}
