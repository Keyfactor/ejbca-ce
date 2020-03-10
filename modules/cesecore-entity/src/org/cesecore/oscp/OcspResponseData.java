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

import javax.persistence.Entity;
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
    
    private static final int LATEST_PROTECT_VERSON = 1;

    private ResponsePK responsePrimaryKey;
    private long producedAt;
    private Long nextUpdate;
    private byte[] ocspResponse;
    private int rowVersion = 0;
    private String rowProtection;

    public OcspResponseData() {
    }

    public OcspResponseData(final ResponsePK pk, final long producedAt, final long nextUpdate, final byte[] ocspResponse) {
        this.responsePrimaryKey = pk;
        this.producedAt = producedAt;
        this.nextUpdate = nextUpdate;
        this.ocspResponse = ocspResponse;
    }

    public ResponsePK getResponsePrimaryKey() {
        return responsePrimaryKey;
    }

    public void setResponsePrimaryKey(final ResponsePK responsePrimaryKey) {
        this.responsePrimaryKey = responsePrimaryKey;
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

    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    @Override
    protected String getProtectString(final int rowversion) {
        final ProtectionStringBuilder protectedStringBuilder = new ProtectionStringBuilder(8000);
        protectedStringBuilder.append(getResponsePrimaryKey().getCaId()).append(getResponsePrimaryKey().getSerialNumber()).append(getProducedAt()).append(getNextUpdate())
                .append(getOcspResponse());
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
        return LATEST_PROTECT_VERSON;
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
        return new ProtectionStringBuilder().append(getResponsePrimaryKey().getCaId()).append(getResponsePrimaryKey().getSerialNumber()).toString();
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
