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
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;

/**
 * A very simple confirmation message, no protection and a nullbody
 * @author tomas
 * @version $Id$
 */
public class CmpConfirmResponseMessage extends BaseCmpMessage implements ResponseMessage {

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

	private static final Logger log = Logger.getLogger(CmpConfirmResponseMessage.class);
	
    /** Default digest algorithm for CMP response message, can be overridden */
	private String digestAlg = CMSSignedGenerator.DIGEST_SHA1;
	/** The default provider is BC, if nothing else is specified when setting SignKeyInfo */
	private String provider = "BC";
	/** Certificate for the signer of the response message (CA) */
	private transient Certificate signCert = null;
	/** Private key used to sign the response message */
	private transient PrivateKey signKey = null;

	/** The encoded response message */
    private byte[] responseMessage = null;

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
	}

	@Override
	public ResponseStatus getStatus() {
		return ResponseStatus.SUCCESS;
	}

	@Override
	public void setFailInfo(FailInfo failInfo) {
	}

	@Override
	public FailInfo getFailInfo() {
		return null;
	}

	@Override
	public void setFailText(String failText) {
	}

	@Override
	public String getFailText() {
		return null;
	}

	@Override
	public boolean create() throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignRequestException {

		final PKIHeaderBuilder myPKIHeader = CmpMessageHelper.createPKIHeaderBuilder(getSender(), getRecipient(), getSenderNonce(), getRecipientNonce(), getTransactionId());
		final PKIBody myPKIBody = new PKIBody(19, new DERNull());
		PKIMessage myPKIMessage = null;

		if ((getPbeDigestAlg() != null) && (getPbeMacAlg() != null) && (getPbeKeyId() != null) && (getPbeKey() != null) ) {
		    myPKIHeader.setProtectionAlg(new AlgorithmIdentifier(getPbeDigestAlg()));
		    myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
			responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, getPbeKeyId(), getPbeKey(), getPbeDigestAlg(), getPbeMacAlg(), getPbeIterationCount());
		} else {
			if ((signCert != null) && (signKey != null)) {
				try {
				    myPKIHeader.setProtectionAlg(new AlgorithmIdentifier(digestAlg));
				    myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
					responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, (X509Certificate)signCert, signKey, digestAlg, provider);
				} catch (CertificateEncodingException e) {
					log.error("Error creating CmpConfirmMessage: ", e);
				} catch (SecurityException e) {
					log.error("Error creating CmpConfirmMessage: ", e);
				} catch (SignatureException e) {
					log.error("Error creating CmpConfirmMessage: ", e);
				}				
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Not signing CMP Confirm Response, because signCert or signKey is not set.");
				}
			}
			// If we could not create the signed response message, create a non-protected one instead.
			if (responseMessage == null) {
				responseMessage = CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);
			}
		}
		return true;
	}

	@Override
	public boolean requireSignKeyInfo() {
		return false;
	}
	
	@Override
	public void setSignKeyInfo(Certificate cert, PrivateKey key, String provider) {
		this.signCert = cert;
		this.signKey = key;
		if (provider != null) {
			this.provider = provider;
		}
	}

	@Override
	public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
	}

	@Override
	public void setPreferredDigestAlg(String digest) {
	}

	@Override
	public void setRequestType(int reqtype) {
	}

	@Override
	public void setRequestId(int reqid) {
	}

	@Override
    public void setProtectionParamsFromRequest(RequestMessage reqMsg) {
    }
}
