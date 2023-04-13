/*************************************************************************
 *                                                                       *
 * Keyfactor Commons                                                     *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificate.x509;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.SecurityFilterInputStream;
import com.keyfactor.util.certificate.CertificateImplementation;

/**
 *
 */
public class X509CertificateUtility implements CertificateImplementation {

    private static final Logger log = Logger.getLogger(X509CertificateUtility.class);
    
    /**
     * 
     */
    public X509CertificateUtility() {
    }

    @Override
    public String getType() {
        return "X.509";
    }
    
    @Override
    public Class<?> getImplementationClass() {
        return X509Certificate.class;
    }

    @Override
    public String getCertificateSignatureAlgorithm(final Certificate certificate) {
        final X509Certificate x509cert = (X509Certificate) certificate;
        String certSignatureAlgorithm = x509cert.getSigAlgName();
        if (log.isDebugEnabled()) {
            log.debug("certSignatureAlgorithm is: " + certSignatureAlgorithm);
        }
        
        return certSignatureAlgorithm;
    }

    @Override
    public String getSubjectDn(final Certificate certificate) {
        final String clazz = certificate.getClass().getName();
        // The purpose of the below generateCertificate is to create a BC certificate object, because there we know how DN components
        // are handled. If we already have a BC certificate however, we can save a lot of time to not have to encode/decode it.
        final X509Certificate x509cert;
        if (clazz.contains("org.bouncycastle")) {
            x509cert = (X509Certificate) certificate;
        } else {
            final CertificateFactory cf = CertTools.getCertificateFactory();
            try {
                x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            } catch (CertificateException e) {
                log.info("Could not get DN from X509Certificate. " + e.getMessage());
                log.debug("", e);
                return null;
            }
        }
        String dn = x509cert.getSubjectDN().toString();
        return CertTools.stringToBCDNString(dn);
    }

    @Override
    public String getIssuerDn(final Certificate certificate) {
        final String clazz = certificate.getClass().getName();
        // The purpose of the below generateCertificate is to create a BC certificate object, because there we know how DN components
        // are handled. If we already have a BC certificate however, we can save a lot of time to not have to encode/decode it.
        final X509Certificate x509cert;
        if (clazz.contains("org.bouncycastle")) {
            x509cert = (X509Certificate) certificate;
        } else {
            final CertificateFactory cf = CertTools.getCertificateFactory();
            try {
                x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            } catch (CertificateException e) {
                log.info("Could not get DN from X509Certificate. " + e.getMessage());
                log.debug("", e);
                return null;
            }
        }
        String dn = x509cert.getIssuerDN().toString();
        return CertTools.stringToBCDNString(dn);
    }

    @Override
    public BigInteger getSerialNumber(final Certificate certificate) {
        X509Certificate xcert = (X509Certificate) certificate;
        return xcert.getSerialNumber();
    }

    @Override
    public String getSerialNumberAsString(final Certificate certificate) {
        X509Certificate xcert = (X509Certificate) certificate;
        return xcert.getSerialNumber().toString(16).toUpperCase();
    }

    @Override
    public byte[] getSignature(final Certificate certificate) {
        X509Certificate xcert = (X509Certificate) certificate;
        return xcert.getSignature();
    }

    @Override
    public Date getNotAfter(final Certificate certificate) {
        final X509Certificate xcert = (X509Certificate) certificate;
        return xcert.getNotAfter();
    }

    @Override
    public Date getNotBefore(final Certificate certificate) {
        X509Certificate xcert = (X509Certificate) certificate;
        return xcert.getNotBefore();
    }

    @Override
    public Certificate parseCertificate(String provider, byte[] cert) throws CertificateParsingException {
        final CertificateFactory cf = CertTools.getCertificateFactory(provider);
        X509Certificate result;
        try {
           result = (X509Certificate) cf.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert)));      
        } catch (CertificateException e) {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
        }
        if(result != null) {
            return result;
        } else {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
        }
    }

    @Override
    public boolean isCA(final Certificate certificate) {
        X509Certificate x509cert = (X509Certificate) certificate;
        return x509cert.getBasicConstraints() > -1;
    }

    @Override
    public void checkValidity(final Certificate certificate, final Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        final X509Certificate xcert = (X509Certificate) certificate;
        xcert.checkValidity(date);
        
    }

    @Override
    public String dumpCertificateAsString(Certificate certificate) {
        try {
            final Certificate c = parseCertificate(BouncyCastleProvider.PROVIDER_NAME, certificate.getEncoded());
            return c.toString();
        } catch (CertificateException e) {
            return e.getMessage();
        }
    }



}
