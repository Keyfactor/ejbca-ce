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
package org.cesecore.oscp;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * 
 * @version $Id$
 *
 */
@Entity
@Table(name = "OcspResponseData")
public class OcspResponseData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(OcspResponseData.class);

    @Id
    @Column(nullable = false)
    private String certificateFingerPrint;
    private long producedAt;
    @Column(nullable = false)
    private long nextUpdate;
    private byte[] ocspResponse;
    private Integer cAId;
    private int rowVersion = 0;
    private String rowProtection;

    public OcspResponseData() {
    }

    public String getCertificateFingerPrint() {
        return this.certificateFingerPrint;
    }

    public void setCertificateFingerPrint(final String fingerPrint) {
        this.certificateFingerPrint = fingerPrint;
    }

    public long getProducedAt() {
        return this.producedAt;
    }

    public void setProducedAt(final long producedAt) {
        this.producedAt = producedAt;
    }

    public long getNextUpdate() {
        return this.nextUpdate;
    }

    public void setNextUpdate(final long nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    public void setOcspResponse(final byte[] ocspResponse) {
        this.ocspResponse = ocspResponse;
    }

    public Integer getCaId() {
        return cAId;
    }

    public void setCaId(final Integer cAId) {
        this.cAId = cAId;
    }

    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }

    @Override
    protected String getProtectString(int rowversion) {
        final ProtectionStringBuilder protectedStringBuilder = new ProtectionStringBuilder(8000);
        protectedStringBuilder.append(getCaId()).append(getCertificateFingerPrint()).append(getProducedAt()).append(getNextUpdate()).append(getOcspResponse());
        if (log.isDebugEnabled()) {
            // Some profiling
            if (protectedStringBuilder.length() > 8000) {
                log.debug("OcspResponseData.getProtectString gives size: " + protectedStringBuilder.length());
            }
        }
        return protectedStringBuilder.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    @Transient
    protected String getRowId() {
        return getCertificateFingerPrint();
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

}
