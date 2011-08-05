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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;

import com.novosec.pkix.asn1.cmp.ErrorMsgContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIFreeText;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;


/**
 * A very simple error message, no protection, or PBE protection
 * @author tomas
 * @version $Id$
 */
public class CmpErrorResponseMessage extends BaseCmpMessage implements ResponseMessage {

	private static Logger log = Logger.getLogger(CmpErrorResponseMessage.class);
	/**
	 * Determines if a de-serialized file is compatible with this class.
	 *
	 * Maintainers must change this value if and only if the new version
	 * of this class is not compatible with old versions. See Sun docs
	 * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
	 * /serialization/spec/version.doc.html> details. </a>
	 *
	 */
	static final long serialVersionUID = 10003L;

	/** The encoded response message */
    private byte[] responseMessage = null;
    private String failText = null;
    private FailInfo failInfo = null;
    private ResponseStatus status = null;
    private int requestId = 0;
	private int requestType = 23; // 23 is general error message

	@Override
    public void setCertificate(Certificate cert) {
	}

	@Override
	public void setCrl(CRL crl) {
	}

	@Override
	public void setIncludeCACert(boolean incCACert) {
	}
	
	@Override
	public void setCACert(Certificate cACert) {
	}

	@Override
	public byte[] getResponseMessage() throws IOException,
			CertificateEncodingException {
        return responseMessage;
	}

	@Override
	public void setStatus(ResponseStatus status) {
		this.status = status;
	}

	@Override
	public ResponseStatus getStatus() {
		return status;
	}

	@Override
	public void setFailInfo(FailInfo failInfo) {
		this.failInfo = failInfo;
	}

	@Override
	public FailInfo getFailInfo() {
		return failInfo;
	}

	@Override
	public void setFailText(String failText) {
		this.failText = failText;
	}

	@Override
	public String getFailText() {
		return failText;
	}

	@Override
	public boolean create() throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignRequestException {
		X509Name sender = X509Name.getInstance(getSender().getName());
		X509Name recipient = X509Name.getInstance(getRecipient().getName());
		PKIHeader myPKIHeader = CmpMessageHelper.createPKIHeader(sender, recipient, getSenderNonce(), getRecipientNonce(), getTransactionId());
		PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(new DERInteger(2)); // 2 = rejection
		if (failInfo != null) {
			myPKIStatusInfo.setFailInfo(failInfo.getAsBitString());			
		}
		if (failText != null) {		
			myPKIStatusInfo.setStatusString(new PKIFreeText(new DERUTF8String(failText)));
		}
		PKIBody myPKIBody = null;
		log.debug("Create error message from requestType: "+requestType);
		if (requestType==0 || requestType==2) {
			myPKIBody = CmpMessageHelper.createCertRequestRejectBody(myPKIHeader, myPKIStatusInfo, requestId, requestType);
		} else {
			ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
			myPKIBody = new PKIBody(myErrorContent, 23); // 23 = error						
		}
		PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		if ((getPbeDigestAlg() != null) && (getPbeMacAlg() != null) && (getPbeKeyId() != null) && (getPbeKey() != null) ) {
			responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, getPbeKeyId(), getPbeKey(), getPbeDigestAlg(), getPbeMacAlg(), getPbeIterationCount());
		} else {
			responseMessage = CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);			
		}
		return true;		
	}

	@Override
	public boolean requireSignKeyInfo() {
		return false;
	}

	@Override
	public void setSignKeyInfo(Certificate cert, PrivateKey key,
			String provider) {
	}

	@Override
	public void setSenderNonce(String senderNonce) {
		super.setSenderNonce(senderNonce);
	}

	@Override
	public void setRecipientNonce(String recipientNonce) {
		super.setRecipientNonce(recipientNonce);
	}

	@Override
	public void setTransactionId(String transactionId) {
		super.setTransactionId(transactionId);
	}

	@Override
	public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
	}

	@Override
	public void setPreferredDigestAlg(String digest) {
	}

	@Override
	public void setRequestType(int reqtype) {
		this.requestType = reqtype;
	}

	@Override
	public void setRequestId(int reqid) {
		this.requestId = reqid;
	}

	@Override
    public void setProtectionParamsFromRequest(RequestMessage reqMsg) {
    }
}
