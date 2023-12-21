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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;

import com.keyfactor.util.CertTools;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;

/**
 * A very simple error message, no protection, or PBE protection
 *
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
    private int requestId = 0;
	private int requestType = 23; // 23 is general error message
    /** Private key used to sign the response message */
    private transient PrivateKey signKey = null;
    /** Signature algorithm normally used to sign with above signKey, for example CAs signatue algorithm */
    private transient String signAlg = null;
	private Collection<Certificate> signCerts = null;
	private String provider = null;
	private String digestAlg = null;


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
	public byte[] getResponseMessage() {
        return responseMessage;
	}

	@Override
	public void setStatus(ResponseStatus status) {
	}

	@Override
	public ResponseStatus getStatus() {
	    // Not used by CMP (create method of this class), but this message is definitely a failure...
		return ResponseStatus.FAILURE;
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
    public boolean create() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		final PKIHeaderBuilder myPKIHeaderBuilder = CmpMessageHelper.createPKIHeaderBuilder(getSender(), getRecipient(), getSenderNonce(), getRecipientNonce(), getTransactionId());
		final boolean pbeProtected = (getPbeDigestAlg() != null) && (getPbeMacAlg() != null) && (getPbeKeyId() != null) && (getPbeKey() != null) ;
		final boolean pbmac1Protected = (getPbmac1PrfAlg() != null) && (getPbmac1MacAlg() != null) && (getPbmac1KeyId() != null)
				&& (getPbmac1Key() != null);
		if(pbeProtected) {
		    myPKIHeaderBuilder.setProtectionAlg(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac));
		}
		PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(PKIStatus.rejection);
		if(failInfo != null && failText != null) {
		    myPKIStatusInfo = new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(new DERUTF8String(failText)), CmpMessageHelper.getPKIFailureInfo(failInfo.intValue()));
		} else if(failText != null) {
		    myPKIStatusInfo = new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(new DERUTF8String(failText)));
		}
		PKIBody myPKIBody = null;
		if (log.isDebugEnabled()) {
		    log.debug("Create error message from requestType: " + requestType);
		}
		if (requestType==0 || requestType==2) {
			myPKIBody = CmpMessageHelper.createCertRequestRejectBody(myPKIStatusInfo, requestId, requestType);
		} else {
			ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
			myPKIBody = new PKIBody(23, myErrorContent); // 23 = error						
		}
		if (pbeProtected) {
			responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(new PKIMessage(myPKIHeaderBuilder.build(), myPKIBody), getPbeKeyId(), getPbeKey(), getPbeDigestAlg(), getPbeMacAlg(),
					getPbeIterationCount());
		} else if (pbmac1Protected) {
			responseMessage = CmpMessageHelper.pkiMessageToByteArray(CmpMessageHelper.protectPKIMessageWithPBMAC1(new PKIMessage(myPKIHeaderBuilder.build(), myPKIBody), getPbmac1KeyId(),
					getPbmac1Key(), getPbmac1MacAlg(), getPbmac1IterationCount(), getPbmac1DkLen(), getPbmac1PrfAlg()));
		}
		else if ((this.signKey != null) && (this.signCerts != null)) {
		    myPKIHeaderBuilder.setSenderKID(CertTools.getSubjectKeyId(signCerts.iterator().next()));
		    PKIMessage myPKIMessage = new PKIMessage(myPKIHeaderBuilder.build(), myPKIBody);
		    try {
		        responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, this.signCerts, this.signKey, signAlg, digestAlg, this.provider);
		    } catch (InvalidKeyException | CertificateEncodingException | NoSuchProviderException | NoSuchAlgorithmException | SecurityException
		              | SignatureException e) {
		        responseMessage = checkAndSendResponseMessage(responseMessage, myPKIHeaderBuilder, myPKIBody, e);
		    }
		    responseMessage = checkAndSendResponseMessage(responseMessage, myPKIHeaderBuilder, myPKIBody, null);
		}
		else {
			responseMessage = CmpMessageHelper.pkiMessageToByteArray(new PKIMessage(myPKIHeaderBuilder.build(), myPKIBody));
		}
		return true;		
	}

	private byte[] checkAndSendResponseMessage(byte[] message, PKIHeaderBuilder myPKIHeaderBuilder, PKIBody myPKIBody, Exception exception) {
	    if ((exception != null) || (message == null)) {
	        if (log.isDebugEnabled()) {
	            log.debug(constructLogMessage(exception));
	        }
	        return responseMessage = CmpMessageHelper.pkiMessageToByteArray(new PKIMessage(myPKIHeaderBuilder.build(), myPKIBody));
	    }
	    return message;
	}

	private String constructLogMessage(Exception exception) {
	    String logMessage = "Could not sign CmpErrorResponseMessage, creating unprotected error message. ";
	    if (exception == null) {
	        return logMessage;
	    }
	    return logMessage + exception.getMessage();
	}

	@Override
	public boolean requireSignKeyInfo() {
		return false;
	}

	@Override
	public void setSignKeyInfo(Collection<Certificate> certs, PrivateKey key, String alg, String provider) {
	    this.signKey = key;
	    this.signAlg = alg;
	    this.signCerts = certs;
	    this.provider = provider;
	}

	@Override
	public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
	}

	@Override
	public void setPreferredDigestAlg(String digest) {
	    this.digestAlg = digest;
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
