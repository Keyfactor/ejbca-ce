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

import com.keyfactor.util.CertTools;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

public class ScpContainerWrapper {
    private final ScpContainer scpContainer;
    private String certificateProfileName;

    public ScpContainerWrapper() {
        this.scpContainer = new ScpContainer();
    }

    public ScpContainerWrapper(final ScpContainer scpContainer) {
        this.scpContainer = scpContainer;
    }

    public ScpContainer toScpContainer() {
        return this.scpContainer;
    }

    public BigInteger getSerialNumber() {
        return this.scpContainer.getSerialNumber();
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.scpContainer.setSerialNumber(serialNumber);
    }

    public String getCertificate() {
        try {
            if (scpContainer.getCertificate() == null) {
                return null;
            }
            return CertTools.getPemFromCertificate(scpContainer.getCertificate());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not decode certificate.", e);
        }
    }

    public void setCertificate(String pemCertificate) {
        try {
            if (pemCertificate == null) {
                this.scpContainer.setCertificate(null);
            } else {
                this.scpContainer.setCertificate(
                        CertTools.getCertfromByteArray(pemCertificate.getBytes(), Certificate.class));
            }
        } catch (CertificateParsingException e) {
            throw new IllegalArgumentException("Could not parse certificate from PEM.", e);
        }
    }

    public float getLatestVersion() {
        return this.scpContainer.getLatestVersion();
    }

    public void setLatestVersion(float latestVersion) {}

    public int getCertificateProfile() {
        return this.scpContainer.getCertificateProfile();
    }

    public void setCertificateProfile(int certificateProfile) {
        this.scpContainer.setCertificateProfile(certificateProfile);
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public int getCertificateStatus() {
        return this.scpContainer.getCertificateStatus();
    }

    public void setCertificateStatus(int certificateStatus) {
        this.scpContainer.setCertificateStatus(certificateStatus);
    }

    public int getCertificateType() {
        return this.scpContainer.getCertificateType();
    }

    public void setCertificateType(int certificateType) {
        this.scpContainer.setCertificateType(certificateType);
    }

    public int getRevocationReason() {
        return this.scpContainer.getRevocationReason();
    }

    public void setRevocationReason(int revocationReason) {
        this.scpContainer.setRevocationReason(revocationReason);
    }

    public long getRevocationDate() {
        return this.scpContainer.getRevocationDate();
    }

    public void setRevocationDate(long revocationDate) {
        this.scpContainer.setRevocationDate(revocationDate);
    }

    public long getUpdateTime() {
        return this.scpContainer.getUpdateTime();
    }

    public void setUpdateTime(long updateTime) {
        this.scpContainer.setUpdateTime(updateTime);
    }

    public String getIssuer() {
        return this.scpContainer.getIssuer();
    }

    public void setIssuer(String issuer) {
        this.scpContainer.setIssuer(issuer);
    }

    public String getSubjectDn() {
        if (this.scpContainer.getCertificate() == null) {
            return null;
        }
        return this.scpContainer.getSubjectDn();
    }

    public void setSubjectDn(String subjectDn) {}

    public String getUsername() {
        return this.scpContainer.getUsername();
    }

    public void setUsername(String username) {
        this.scpContainer.setUsername(username);
    }
}