/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.FailInfo;

/**
 * Return additional fields needed for the Intune SCEP integration.
 */
public class IntuneScepDispatchResponse implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(IntuneScepDispatchResponse.class);

    private boolean failed = false;
    private byte[] pkcs7Response;
    private X500Principal issuer = null;
    private BigInteger serialNumber= null;
    private Instant notAfter = null;
    private byte[] thumbprint = null;
    private FailInfo failInfo = null;
    private String failText = null;

    public IntuneScepDispatchResponse(byte[] pkcs7Response) {
        this.pkcs7Response = pkcs7Response;
        failed = false;
    }

    public IntuneScepDispatchResponse(byte[] pkcs7Response, X500Principal issuer, BigInteger serialNumber, Instant notAfter,
            byte[] thumbprint) {
        this.pkcs7Response = pkcs7Response;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notAfter = notAfter;
        this.thumbprint = thumbprint;
        failed = false;
    }

    public IntuneScepDispatchResponse(byte[] pkcs7Response, X509Certificate issuedCert) {
        this.pkcs7Response = pkcs7Response;
        this.issuer = issuedCert.getIssuerX500Principal();
        this.serialNumber = issuedCert.getSerialNumber();
        this.notAfter = issuedCert.getNotAfter().toInstant();
        try {
            this.thumbprint = MessageDigest.getInstance("SHA-1").digest(issuedCert.getEncoded());
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            log.error("Unexpected error when creating SHA-1 thumbprint of certificate: " + issuedCert.getSubjectDN(), e);
        }
        failed = false;
    }

    public IntuneScepDispatchResponse(byte[] ret, FailInfo failInfo, String failText) {
        this.pkcs7Response = ret;
        this.failInfo = failInfo;
        this.failText = failText;
        failed = true;
    }

    public byte[] getThumbprint() {
        return thumbprint;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public X500Principal getIssuer() {
        return issuer;
    }

    public final byte[] getPkcs7Response() {
        return pkcs7Response;
    }

    public final Instant getNotAfter() {
        return notAfter;
    }

    public final boolean isFailed() {
        return failed;
    }

    public final FailInfo getFailInfo() {
        return failInfo;
    }

    public final String getFailText() {
        return failText;
    }
}
