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
package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;


/**
 * A very simple confirmation message, no protection and a nullbody
 * @author tomas
 * @version $Id: CmpConfirmResponseMessage.java,v 1.1 2006-09-21 11:33:33 anatom Exp $
 */
public class CmpConfirmResponseMessage extends BaseCmpMessage implements IResponseMessage {

    /** The encoded response message */
    private byte[] responseMessage = null;

    public void setCertificate(Certificate cert) {
	}

	public void setCrl(CRL crl) {
	}

	public void setIncludeCACert(boolean incCACert) {
	}

	public byte[] getResponseMessage() throws IOException,
			CertificateEncodingException {
        return responseMessage;
	}

	public void setStatus(ResponseStatus status) {
	}

	public ResponseStatus getStatus() {
		return null;
	}

	public void setFailInfo(FailInfo failInfo) {
	}

	public FailInfo getFailInfo() {
		return null;
	}

	public void setFailText(String failText) {
	}

	public String getFailText() {
		return null;
	}

	public boolean create() throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignRequestException, NotFoundException {

		X509Name sender = X509Name.getInstance(getSender().getName());
		X509Name recipient = X509Name.getInstance(getRecipient().getName());
		PKIHeader myPKIHeader = CmpMessageHelper.createPKIHeader(sender.toString(), recipient.toString(), getSenderNonce(), getRecipientNonce(), getTransactionId());
		PKIBody myPKIBody = new PKIBody(new DERNull(), 19);
		PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DEROutputStream mout = new DEROutputStream( baos );
		mout.writeObject( myPKIMessage );
		mout.close();
		responseMessage = baos.toByteArray();		
		return true;
	}

	public boolean requireSignKeyInfo() {
		return false;
	}

	public boolean requireEncKeyInfo() {
		return false;
	}

	public void setSignKeyInfo(X509Certificate cert, PrivateKey key,
			String provider) {
	}

	public void setEncKeyInfo(X509Certificate cert, PrivateKey key,
			String provider) {
	}

	public void setSenderNonce(String senderNonce) {
		super.setSenderNonce(senderNonce);
	}

	public void setRecipientNonce(String recipientNonce) {
		super.setRecipientNonce(recipientNonce);
	}

	public void setTransactionId(String transactionId) {
		super.setTransactionId(transactionId);
	}

	public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
	}

	public void setPreferredDigestAlg(String digest) {
	}

	public void setRequestType(int reqtype) {
	}

	public void setRequestId(int reqid) {
	}

}
