/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.request;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.util.CertTools;

/**
 * A response message consisting of a single X509 or CVC Certificate. Name is nowadays slightly misleading since the class can 
 * care any type of "Certificate", for example a CV certificate.
 *
 * @version $Id$
 */
public class X509ResponseMessage implements CertificateResponseMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = -2157072605987735913L;

    private static Logger log = Logger.getLogger(X509ResponseMessage.class);

    /** Certificate to be in response message, */
    private Certificate cert = null;

    /** status for the response */
    private ResponseStatus status = ResponseStatus.SUCCESS;

    /** Possible fail information in the response. Defaults to null. */
    private FailInfo failInfo = null;

    /** Possible clear text error information in the response. Defaults to null. */
    private String failText = null;
    
    private transient CertificateData certificateData;
    private transient Base64CertData base64CertData;
    
    @Override
    public CertificateData getCertificateData() {
        return certificateData;
    }
    
    @Override
    public void setCertificateData(CertificateData certificateData) {
        if (certificateData != null) {
            this.certificateData = new CertificateData(certificateData);
        } else {
            this.certificateData = null;
        }
    }
    
    @Override
    public Base64CertData getBase64CertData() {
        return base64CertData;
    }
    
    @Override
    public void setBase64CertData(final Base64CertData base64CertData) {
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }

    /**
     * Sets the complete certificate in the response message.
     *
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }

    /**
     * Sets the CRL (if present) in the response message.
     *
     * @param crl crl in the response message.
     */
    public void setCrl(CRL crl) {
        // This message type does not contain a CRL
    }

    /** @see org.cesecore.certificates.certificate.request.ResponseMessage.protocol.IResponseMessage#setIncludeCACert
     * 
     */
    public void setIncludeCACert(boolean incCACert) {
    	// Do nothing, not applicable
    }
	public void setCACert(Certificate cACert) {
	}

    @Override
    public Certificate getCertificate() {     
        try {
            return CertTools.getCertfromByteArray(getResponseMessage(), Certificate.class);
        } catch (CertificateEncodingException e) {
            throw new Error("Could not encode certificate. This should not happen", e);
        } catch (CertificateException e) {
            throw new Error("Response was created without containing valid certificate. This should not happen", e);
        }
    }

    @Override
    public byte[] getResponseMessage() throws CertificateEncodingException {
        return cert.getEncoded();
    }

    /**
     * Sets the status of the response message.
     *
     * @param status status of the response.
     */
    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    /**
     * Gets the status of the response message.
     *
     * @return status status of the response.
     */
    public ResponseStatus getStatus() {
        return status;
    }

    /**
     * Sets info about reason for failure.
     *
     * @param failInfo reason for failure.
     */
    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    /**
     * Gets info about reason for failure.
     *
     * @return failInfo reason for failure.
     */
    public FailInfo getFailInfo() {
        return failInfo;
    }

    public void setFailText(String failText) {
    	this.failText = failText;
    }

    public String getFailText() {
    	return this.failText;
    }

    /**
     * Create encrypts and creates signatures as needed to produce a complete response message.  If
     * needed setSignKeyInfo must be called before this method. After this is
     * called the response message can be retrieved with getResponseMessage();
     *
     * @return True if signature/encryption was successful, false if it failed, request should not
     *         be sent back i failed.
     *
     * @throws IOException If input/output or encoding failed.
     * @throws InvalidKeyException If the key used for signing/encryption is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     *
     * @see #setSignKeyInfo()
     */
    public boolean create() {

        if (status.equals(ResponseStatus.SUCCESS)) {
            log.debug("Creating a STATUS_OK message.");
        } else {
            if (status.equals(ResponseStatus.FAILURE)) {
                log.debug("Creating a STATUS_FAILED message (or throwing an exception).");
                if (failInfo.equals(FailInfo.WRONG_AUTHORITY)) {
                    return false;
                }
                if (failInfo.equals(FailInfo.INCORRECT_DATA)) {
                    return false;
                }
            } else {
                log.debug("Creating a STATUS_PENDING message.");
            }
        }
        return true;
    }

    /**
     * indicates if this message needs recipients public and private key to sign. If this returns
     * true, setSignKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo() {
        return false;
    }

    /**
     * Sets the public and private key needed to sign the message. Must be set if
     * requireSignKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireSignKeyInfo()
     */
    public void setSignKeyInfo(Collection<Certificate> certs, PrivateKey key, String provider) {
    }

    /**
     * Sets a senderNonce if it should be present in the response
     *
     * @param senderNonce a string of base64 encoded bytes
     */
    public void setSenderNonce(String senderNonce) {
    }

    /**
     * Sets a recipient if it should be present in the response
     *
     * @param recipientNonce a string of base64 encoded bytes
     */
    public void setRecipientNonce(String recipientNonce) {
    }

    /**
     * Sets a transaction identifier if it should be present in the response
     *
     * @param transactionId transaction id
     */
    public void setTransactionId(String transactionId) {
    }

    /**
     * Sets recipient key info, key id or similar. This is usually the request key info from the
     * request message.
     *
     * @param recipientKeyInfo key info
     */
    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
    }
    
    /** @see org.cesecore.certificates.certificate.request.ResponseMessage.core.protocol.IResponseMessage
     */
    public void setPreferredDigestAlg(String digest) {
    }

    /** @see org.cesecore.certificates.certificate.request.ResponseMessage.core.protocol.IResponseMessage
     */
    public void setRequestType(int reqtype) {
	}

    /** @see org.cesecore.certificates.certificate.request.ResponseMessage.core.protocol.IResponseMessage
     */
    public void setRequestId(int reqid) {
    }

    /** @see org.cesecore.certificates.certificate.request.ResponseMessage.core.protocol.IResponseMessage
     */
    public void setProtectionParamsFromRequest(RequestMessage reqMsg) {
    }
}
