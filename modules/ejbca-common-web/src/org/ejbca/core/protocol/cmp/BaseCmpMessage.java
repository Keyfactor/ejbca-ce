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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * 
 * @version $Id$
 *
 */

public abstract class BaseCmpMessage implements Serializable {

	private static final long serialVersionUID = 1L;

	private transient PKIMessage msg = null;
	private String b64SenderNonce = null;
	private String b64RecipientNonce = null;
	private String b64TransId = null;
	private transient GeneralName recipient = null;	// GeneralName is not Serializable
	private byte[] recipientBytes = null;
	private transient GeneralName sender = null;	// GeneralName is not Serializable
	private byte[] senderBytes = null;
	private String protectionType = null;
	private String pbeDigestAlg = null;
	private String pbeMacAlg = null;
	private int pbeIterationCount = 1024;
	private String pbeKeyId = null;
	private String pbeKey = null;

	public void setSenderNonce(String b64nonce) {
		this.b64SenderNonce = b64nonce;
	}
	public String getSenderNonce() {
		return b64SenderNonce;
	}
	public void setRecipientNonce(String b64nonce) {
		this.b64RecipientNonce = b64nonce;
	}
	public String getRecipientNonce() {
		return b64RecipientNonce;
	}

	public void setTransactionId(String b64transid) {
		this.b64TransId = b64transid;
	}
	public String getTransactionId() {
		return b64TransId;
	}

	public GeneralName getRecipient() {
		if (recipient == null && recipientBytes != null) {
			ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(recipientBytes));
			try {
				recipient = GeneralName.getInstance(ais.readObject());
				ais.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return recipient;
	}
	public void setRecipient(GeneralName recipient) {
		this.recipient = recipient;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ASN1OutputStream aos = new ASN1OutputStream(baos);
		try {
			aos.writeObject(recipient);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		recipientBytes = baos.toByteArray();
	}
	public GeneralName getSender() {
		if (sender == null && senderBytes != null) {
			ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(senderBytes));
			try {
				sender = GeneralName.getInstance(ais.readObject());
				ais.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return sender;
	}
	public void setSender(GeneralName sender) {
		this.sender = sender;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ASN1OutputStream aos = new ASN1OutputStream(baos);
		try {
			aos.writeObject(sender);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		senderBytes = baos.toByteArray();
	}
	public PKIHeader getHeader() {
		return msg.getHeader();
	}
	public PKIMessage getMessage() {
		return msg;
	}
	public void setMessage(PKIMessage msg) {
		this.msg = msg;
	}
	public String getProtectionType() {
		return protectionType;
	}
	public void setProtectionType(String protectionType) {
		this.protectionType = protectionType;
	}
	public void setPbeParameters(final String keyId, final String key, final String digestAlg, final String macAlg, final int iterationCount) {
		this.pbeKeyId = keyId;
		this.pbeKey = key;
		this.pbeDigestAlg = digestAlg;
		this.pbeMacAlg = macAlg;
		this.pbeIterationCount = iterationCount;
	}
	public String getPbeDigestAlg() {
		return pbeDigestAlg;
	}
	public String getPbeKey() {
		return pbeKey;
	}
	public String getPbeKeyId() {
		return pbeKeyId;
	}
	public String getPbeMacAlg() {
		return pbeMacAlg;
	}
	public int getPbeIterationCount() {
		return pbeIterationCount;
	}
}
