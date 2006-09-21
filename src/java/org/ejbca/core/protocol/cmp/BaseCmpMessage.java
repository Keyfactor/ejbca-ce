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

import org.bouncycastle.asn1.x509.GeneralName;

public abstract class BaseCmpMessage {

	private String b64SenderNonce = null;
	private String b64RecipientNonce = null;
	private String b64TransId = null;
	private GeneralName recipient = null;
	private GeneralName sender = null;

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
		return recipient;
	}
	public void setRecipient(GeneralName recipient) {
		this.recipient = recipient;
	}
	public GeneralName getSender() {
		return sender;
	}
	public void setSender(GeneralName sender) {
		this.sender = sender;
	}
	
	
}
