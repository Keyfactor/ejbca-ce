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

public class ScepDispatchResponse implements Serializable {

    private static final Logger log = Logger.getLogger(ScepDispatchResponse.class);

    private byte[] pkcs7Response;
    private X500Principal issuer = null;
    private BigInteger serialNumber= null;
    private Instant notAfter = null;
    private byte[] thumbprint = null;

    public ScepDispatchResponse(byte[] pkcs7Response) {
        this.pkcs7Response = pkcs7Response;
    }

    public ScepDispatchResponse(byte[] pkcs7Response, X500Principal issuer, BigInteger serialNumber, Instant notAfter,
            byte[] thumbprint) {
        this.pkcs7Response = pkcs7Response;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notAfter = notAfter;
        this.thumbprint = thumbprint;
    }

    public ScepDispatchResponse(byte[] pkcs7Response, X509Certificate issuedCert) {
        this.pkcs7Response = pkcs7Response;
        this.issuer = issuedCert.getIssuerX500Principal();
        this.serialNumber = issuedCert.getSerialNumber();
        this.notAfter = issuedCert.getNotAfter().toInstant();
        try {
            this.thumbprint = MessageDigest.getInstance("SHA-1").digest(issuedCert.getEncoded());
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            log.error("Unexpected error when creating SHA-1 thumbprint of certificate: " + issuedCert.getSubjectDN(), e);
        }
    }

    public byte[] getResponseBytes() {
        return pkcs7Response;
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
}
