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
import java.util.List;

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
    private byte[] certbytes = null;

    /** status for the response */
    private ResponseStatus status = ResponseStatus.SUCCESS;

    /** Possible fail information in the response. Defaults to null. */
    private FailInfo failInfo = null;

    /** Possible clear text error information in the response. Defaults to null. */
    private String failText = null;
    
    private transient Certificate certificate;
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
     * @param certificate certificate in the response message.
     */
    @Override
    public void setCertificate(final Certificate certificate) {
        this.certificate = certificate;
        try {
            this.certbytes = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not encode certificate. This should not happen", e);
        }
    }

    @Override
    public void setCrl(CRL crl) {
        // This message type does not contain a CRL
    }

    @Override
    public void setIncludeCACert(boolean incCACert) {
        // Do nothing, not applicable
    }
    @Override
    public void setCACert(Certificate cACert) {
    }

    @Override
    public Certificate getCertificate() {
        // Deserialize certificate using BC if this entire object has been serialized
        if (certificate==null) {
            try {
                certificate = CertTools.getCertfromByteArray(certbytes, Certificate.class);
            } catch (CertificateException e) {
                throw new Error("Response was created without containing valid certificate. This should not happen", e);
            }
        }
        return certificate;
    }

    @Override
    public byte[] getResponseMessage() {
        return certbytes;
    }

    /**
     * Sets the status of the response message.
     *
     * @param status status of the response.
     */
    @Override
    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    /**
     * Gets the status of the response message.
     *
     * @return status status of the response.
     */
    @Override
    public ResponseStatus getStatus() {
        return status;
    }

    /**
     * Sets info about reason for failure.
     *
     * @param failInfo reason for failure.
     */
    @Override
    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    /**
     * Gets info about reason for failure.
     *
     * @return failInfo reason for failure.
     */
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

    /**
     * Create encrypts and creates signatures as needed to produce a complete response message.  If
     * needed setSignKeyInfo must be called before this method. After this is
     * called the response message can be retrieved with getResponseMessage();
     *
     * @return True if signature/encryption was successful, false if it failed, request should not
     *         be sent back if failed.
     *
     * @throws IOException If input/output or encoding failed.
     * @throws InvalidKeyException If the key used for signing/encryption is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     *
     * @see #setSignKeyInfo()
     */
    @Override
    public boolean create() {
        if (status.equals(ResponseStatus.SUCCESS)) {
            log.debug("Creating a STATUS_OK message.");
        } else {
            if (status.equals(ResponseStatus.FAILURE)) {
                if (log.isDebugEnabled()) {
                    log.debug("Creating a STATUS_FAILED message (or throwing an exception): " + failInfo);
                }
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
    @Override
    public boolean requireSignKeyInfo() {
        return false;
    }

    @Override
    public void setSignKeyInfo(Collection<Certificate> certs, PrivateKey key, String provider) {
    }

    @Override
    public void setSenderNonce(String senderNonce) {
    }

    @Override
    public void setRecipientNonce(String recipientNonce) {
    }

    @Override
    public void setTransactionId(String transactionId) {
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
    
    @Override
    public void addAdditionalCaCertificates(final List<Certificate> certificates) {
        // NOOP. Only for CMP.
    }

    @Override
    public void addAdditionalResponseExtraCertsCertificates(List<Certificate> certificates) {
        // NOOP. Only for CMP.
    }
}
