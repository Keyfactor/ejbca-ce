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
package org.ejbca.scp.publisher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.CertTools;

/**
 * Provides a serializable POJO for transmitting certificate information over SCP 
 * 
 * @version $Id$
 *
 */
public class ScpContainer extends UpgradeableDataHashMap implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final String ISSUER = "issuer";
    private static final String SERIAL_NUMBER = "serial.number";
    private static final String REVOCATION_DATE = "revocation.date";
    private static final String REVOCATION_REASON = "revocation.reason";
    private static final String CERTIFICATE_STATUS = "certificate.status";
    private static final String CERTIFICATE_TYPE = "certificate.type";
    private static final String CERTIFICATE = "certificate";
    private static final String USERNAME = "username";
    private static final String CERTIFICATE_PROFILE = "certificate.profile";
    private static final String UPDATE_TIME = "update.time";


    @Override
    public float getLatestVersion() {
        return 0;
    }


    @Override
    public void upgrade() {

    }
    
    /** Issuer DN, BouncyCastle formatted */
    public ScpContainer setIssuer(final String issuer) {
        data.put(ISSUER, issuer);
        return this;
    }
    
    /** Issuer DN, BouncyCastle formatted */
    public String getIssuer() {
        return (String) data.get(ISSUER);
    }
    
    public ScpContainer setUsername(final String username) {
        data.put(USERNAME, username);
        return this;
    }
    
    public String getUsername() {
        return (String) data.get(USERNAME);
    }
    
    public ScpContainer setSerialNumber(final BigInteger serialNumber) {
        data.put(SERIAL_NUMBER, serialNumber);
        return this;
    }
    
    public BigInteger getSerialNumber() {
        return (BigInteger) data.get(SERIAL_NUMBER);
    }
    
    public ScpContainer setRevocationDate(final long revocationDate) {
        data.put(REVOCATION_DATE, revocationDate);
        return this;
    }
    
    public long getRevocationDate() {
        return (long) data.get(REVOCATION_DATE);
    }
    
    public ScpContainer setRevocationReason(final int revocationReason) {
        data.put(REVOCATION_REASON, revocationReason);
        return this;
    }
    
    public long getUpdateTime() {
        return (long) data.get(UPDATE_TIME);
    }
    
    public ScpContainer setUpdateTime(final long updateTime) {
        data.put(UPDATE_TIME, updateTime);
        return this;
    }
    
    public int getRevocationReason() {
        return (int) data.get(REVOCATION_REASON);
    }
    
    public ScpContainer setCertificateStatus(final int certificateStatus) {
        data.put(CERTIFICATE_STATUS, certificateStatus);
        return this;
    }
    
    public int getCertificateStatus() {
        return (int) data.get(CERTIFICATE_STATUS);
    }
    
    public ScpContainer setCertificateType(final int certificateType) {
        data.put(CERTIFICATE_TYPE, certificateType);
        return this;
    }
    
    public int getCertificateType() {
        return (int) data.get(CERTIFICATE_TYPE);
    }
    
    public ScpContainer setCertificateProfile(final int certificateProfile) {
        data.put(CERTIFICATE_PROFILE, certificateProfile);
        return this;
    }
    
    public int getCertificateProfile() {
        return (int) data.get(CERTIFICATE_PROFILE);
    }
    
    
    public String getSubjectDn() {
        try {
            return CertTools.getSubjectDN(CertTools.getCertfromByteArray((byte[])data.get(CERTIFICATE), Certificate.class));
        } catch (CertificateParsingException e) {
            throw new IllegalStateException("Could not decode certificate.", e);
        }
    }
    
    public ScpContainer setCertificate(final Certificate certificate) {
        if (certificate == null) {
            data.put(CERTIFICATE, null);
        } else {
            try {
                data.put(CERTIFICATE, certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Could not encode certificate: " + certificate.toString(), e);
            }
        }
        return this;
    }
    
    public Certificate getCertificate() {
        byte[] encodedCertificate = (byte[]) data.get(CERTIFICATE);
        if (encodedCertificate == null) {
            return null;
        } else {
            try {
                return CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            } catch (CertificateParsingException e) {
                throw new IllegalStateException("Could not decode certificate.", e);
            }
        }
    }

    /**
     * 
     * @return this object as a byte array
     * @throws IOException if this object could not be encoded
     */
    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] encodedObject;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this);
            out.flush();
            encodedObject = bos.toByteArray();
        } finally {
            try {
                bos.close();
            } catch (IOException ex) {
                // NOPMD: ignore close exception
            }
        }
        return encodedObject;
    }

}
