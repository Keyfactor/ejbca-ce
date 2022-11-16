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
package org.cesecore.certificates.certificate.ssh;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;

import com.keyfactor.util.certificate.CertificateImplementation;

/**
 *
 */
public class SshCertificateUtility implements CertificateImplementation {

    /**
     * 
     */
    public SshCertificateUtility() {
    }

    @Override
    public String getType() {
        return SshCertificate.CERTIFICATE_TYPE;
    }

    @Override
    public Class<?> getImplementationClass() {
        return SshCertificate.class;
    }

    @Override
    public String getCertificateSignatureAlgorithm(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getSubjectDn(Certificate certificate) {
        return "CN=" + ((SshCertificate) certificate).getKeyId();
    }

    @Override
    public String getIssuerDn(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public BigInteger getSerialNumber(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getSerialNumberAsString(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] getSignature(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date getNotAfter(Certificate certificate) {
        return ((SshCertificate) certificate).getValidBefore();
    }

    @Override
    public Date getNotBefore(Certificate certificate) {
        return ((SshCertificate) certificate).getValidBefore();
    }

    @Override
    public Certificate parseCertificate(String provider, byte[] cert) throws CertificateParsingException {
        // SSH certificates have human readable prefix e.g. ssh-rsa|ed25519 or ecdsa-ssh 
        if((cert[0]=='s' && cert[1]=='s' && cert[2]=='h') ||
                (cert[0]=='e' && cert[1]=='c' && cert[2]=='d' && cert[3]=='s' && cert[4]=='a')) {
            try {
                return (Certificate) SshCertificateFactory.INSTANCE.getSshCertificate(cert);
            } catch (Exception e) {
                // NOPMD
            }
        }
        return null;
    }

    @Override
    public boolean isCA(Certificate certificate) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void checkValidity(Certificate certificate, Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        // TODO Auto-generated method stub

    }

    @Override
    public String dumpCertificateAsString(Certificate certificate) {
        // TODO Auto-generated method stub
        return null;
    }

}
