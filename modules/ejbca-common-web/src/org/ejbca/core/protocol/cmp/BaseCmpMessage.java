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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.util.Base64;

/**
 * Base class for CMP request messages.
 * 
 * @version $Id$
 */
public abstract class BaseCmpMessage implements Serializable {

	private static final long serialVersionUID = 1L;

	private transient PKIMessage pkiMessage = null;
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

	/** @return the ASN.1 encoded octets as a bas64 encoded String or null if no such data is available */
	protected String getBase64FromAsn1OctetString(final ASN1OctetString asn1OctetString) {
        if (asn1OctetString != null) {
            final byte[] val = asn1OctetString.getOctets();
            if (val != null) {
                return new String(Base64.encode(val));
            }
        }
        return null;
	}
	/** @return the byte array representation of the ASN.1 object */
    private byte[] getByteArrayFromAsn1Encodable(final ASN1Encodable asn1Encodable) throws IllegalStateException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new ASN1OutputStream(baos).writeObject(asn1Encodable);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

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
            recipient = GeneralName.getInstance(recipientBytes);
		}
		return recipient;
	}
	public void setRecipient(final GeneralName recipient) {
		this.recipient = recipient;
		recipientBytes = getByteArrayFromAsn1Encodable(recipient);
	}
	public GeneralName getSender() {
		if (sender == null && senderBytes != null) {
            sender = GeneralName.getInstance(senderBytes);
		}
		return sender;
	}
	public void setSender(final GeneralName sender) {
		this.sender = sender;
		senderBytes = getByteArrayFromAsn1Encodable(sender);
	}
	public PKIHeader getHeader() {
		return pkiMessage.getHeader();
	}
	public PKIMessage getMessage() {
		return pkiMessage;
	}
	public void setMessage(final PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
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
