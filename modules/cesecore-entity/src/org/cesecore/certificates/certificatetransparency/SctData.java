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
package org.cesecore.certificates.certificatetransparency;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.cesecore.util.GUIDGenerator;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import java.io.Serializable;

/**
 * A storage of SCT (signed certificate timestamp from a CT log) data
 *
 * @version $Id$
 */
@Entity
@Table(name = "SctData")
public class SctData extends ProtectedData implements Serializable {
    private static final Logger log = Logger.getLogger(SctData.class);

    private static final long serialVersionUID = 1L;

    private static final int LATEST_PROTECT_VERSON = 1;

    private String pk;
    private String fingerprint;
    private int logId;
    private long certificateExpirationDate;
    private String data;

    private int rowVersion = 0;
    private String rowProtection;


    public SctData() {
    }

    public SctData(String fingerprint, int logId, long certificateExpirationDate, String data) {
        this.pk = GUIDGenerator.generateGUID(this);
        this.fingerprint = fingerprint;
        this.logId = logId;
        this.certificateExpirationDate = certificateExpirationDate;
        this.data = data;
    }

    public String getPk() {
        return pk;
    }

    public void setPk(String pk) {
        this.pk = pk;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public int getLogId() {
        return logId;
    }

    public void setLogId(int logId) {
        this.logId = logId;
    }

    public long getCertificateExpirationDate() {
        return certificateExpirationDate;
    }

    public void setCertificateExpirationDate(long certificateExpirationDate) {
        this.certificateExpirationDate = certificateExpirationDate;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }

    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    public void setRowProtection(String rowProtection) {
        this.rowProtection = rowProtection;
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking so we will not include that in the database protection
        return new ProtectionStringBuilder().append(getFingerprint())
                .append(getLogId())
                .append(getCertificateExpirationDate())
                .append(getData()).toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return LATEST_PROTECT_VERSON;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return new ProtectionStringBuilder().append(getFingerprint()).append(getLogId()).toString();
    }

    //
    // End Database integrity protection methods
    //

    @Transient
    public void setScts(byte[] ctLogs) {
       this.data = new String(Base64.encode(ctLogs, true));
    }

    @Transient
    public byte[] getScts() {
        return Base64.decode(data.getBytes());
    }
}
