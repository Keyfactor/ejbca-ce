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

import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.List;

import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;

/**
 * SSH Response message.
 *
 * @version $Id$
 */
public class SshResponseMessage implements CertificateResponseMessage{

    private static final long serialVersionUID = 1L;

    /** Certificate to be in response message, */
    private byte[] encodedSshCertificate = null;

    @Override
    public void setCrl(CRL crl) {
    }

    @Override
    public void setIncludeCACert(boolean incCACert) {
    }

    @Override
    public void setCACert(Certificate caCert) {
    }

    @Override
    public byte[] getResponseMessage() {
        return encodedSshCertificate;
    }

    @Override
    public void setStatus(ResponseStatus status) {
    }

    @Override
    public ResponseStatus getStatus() {
        return null;
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
    public boolean create() {
        return false;
    }

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
    public Certificate getCertificate() {
        return null;
    }

    @Override
    public void setCertificate(Certificate cert) {
        try {
            this.encodedSshCertificate = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not encode SSH certificate.", e);
        }
    }

    @Override
    public CertificateData getCertificateData() {
        return null;
    }

    @Override
    public void setCertificateData(CertificateData certificateData) {
    }

    @Override
    public Base64CertData getBase64CertData() {
        return null;
    }

    @Override
    public void setBase64CertData(Base64CertData base64CertData) {
    }

    @Override
    public void addAdditionalCaCertificates(List<Certificate> certificates) {
    }

    @Override
    public void addAdditionalResponseExtraCertsCertificates(List<Certificate> certificates) {
    }

}
