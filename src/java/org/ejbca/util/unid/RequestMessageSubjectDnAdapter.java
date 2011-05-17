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
		final X509Name name = getRequestX509Name();
		if ( name==null ) {
			return null;
		}
		return CertTools.stringToBCDNString(name.toString());
	}
	@Override
	public X509Name getRequestX509Name() {
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
	public X509Extensions getRequestExtensions() {
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
	public IResponseMessage createResponseMessage(Class responseClass,
			IRequestMessage req, Certificate cert, PrivateKey signPriv,
			String provider) {
		return this.original.createResponseMessage(responseClass, req, cert, signPriv, provider);
	}		
}
