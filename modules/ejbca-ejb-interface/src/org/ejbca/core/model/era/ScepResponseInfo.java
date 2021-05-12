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
 * Return additional fields needed for some SCEP integrations.
 */
public class ScepResponseInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(ScepResponseInfo.class);

    // this will always be set
    private byte[] pkcs7Response;

    // additional fields set with SCEP issues a certificate
    private boolean failed = false;
    private byte[] pkcs10Request = null;
    private X500Principal issuer = null;
    private BigInteger serialNumber = null;
    private Instant notAfter = null;
    private byte[] thumbprint = null;
    private FailInfo failInfo = null;
    private String failText = null;

    public ScepResponseInfo(byte[] pkcs7Response, X500Principal issuer, BigInteger serialNumber, Instant notAfter, byte[] thumbprint,
            byte[] pkcs10Request) {
        this.pkcs10Request = pkcs10Request;
        this.pkcs7Response = pkcs7Response;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notAfter = notAfter;
        this.thumbprint = thumbprint;
        failed = false;
    }

    public ScepResponseInfo(byte[] pkcs7Response, X509Certificate issuedCert, byte[] pkcs10Request) {
        this.pkcs10Request = pkcs10Request;
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

    public ScepResponseInfo(byte[] pkcs7Response, FailInfo failInfo, String failText, byte[] pkcs10Request) {
        this.pkcs10Request = pkcs10Request;
        this.pkcs7Response = pkcs7Response;
        this.failInfo = failInfo;
        if (failText != null)
            this.failText = failText;
        else
            this.failText = failInfo.toString();
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

    public byte[] getPkcs10Request() {
        return pkcs10Request;
    }

    private ScepResponseInfo(byte[] response) {
        this.pkcs7Response = response;
    }

    /**
     * No additional fields are set - this will only hold the response for the client.
     * 
     * @param response response to be send to client
     * @return a ScepResponseInfo that only holds the byte to be sent to the client
     */
    public static ScepResponseInfo onlyResponseBytes(byte[] response) {
        return new ScepResponseInfo(response);
    }

}
