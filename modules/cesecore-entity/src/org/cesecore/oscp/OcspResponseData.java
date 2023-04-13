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
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.NamedNativeQueries;
import javax.persistence.NamedNativeQuery;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.Index;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.ConstructorResult;
import javax.persistence.ColumnResult;

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
@Table(name = "OcspResponseData", indexes = { 
        @Index(columnList = "caId", name = "ocspresponsedata_idx1"),
        @Index(columnList = "serialNumber", name = "ocspresponsedata_idx2"),
        @Index(columnList = "producedAt", name = "ocspresponsedata_idx3")})
@NamedQueries({ 
        @NamedQuery(name = "findOcspDataByCaId", query = "SELECT a FROM OcspResponseData a WHERE a.caId = :caId"),
        @NamedQuery(name = "findOcspDataById", query = "SELECT a FROM OcspResponseData a WHERE a.id = :id"),
        @NamedQuery(name = "findOcspDataBySerialNumber", query = "SELECT a FROM OcspResponseData a WHERE a.serialNumber = :serialNumber"),
        @NamedQuery(name = "findOcspDataByCaIdSerialNumber", query = "SELECT a FROM OcspResponseData a WHERE a.caId = :caId AND a.serialNumber = :serialNumber ORDER BY a.producedAt DESC"),
        @NamedQuery(name = "deleteOcspDataByCaId", query = "DELETE FROM OcspResponseData a WHERE a.caId = :caId"),
        @NamedQuery(name = "deleteOcspDataBySerialNumber", query = "DELETE FROM OcspResponseData a WHERE a.serialNumber = :serialNumber"),
        @NamedQuery(name = "deleteOcspDataByCaIdSerialNumber", query = "DELETE FROM OcspResponseData a WHERE a.caId = :caId AND a.serialNumber = :serialNumber"), })
@NamedNativeQueries({
        // See comments below for the limitations due to different supported database engines and JPQL.
        // JPQL doesn't support inner joins that uses subqueries.
        @NamedNativeQuery(name = OcspResponseData.FIND_EXPIRING_OCPS_DATA_BY_CAID,
                          query = "SELECT * FROM OcspResponseData ocsp INNER JOIN (" +
                                  "     SELECT serialNumber, MAX(producedAt) as maximumProducedAt FROM OcspResponseData GROUP BY serialNumber" +
                                  ") maxProducedAtTable " +
                                  "ON ocsp.serialNumber = maxProducedAtTable.serialNumber AND ocsp.producedAt = maxProducedAtTable.maximumProducedAt " +
                                  "WHERE cAId = :caId AND ocsp.nextUpdate <= :expirationDate",
                          resultSetMapping = "OcspResponseData"),

        // ORACLE   : It doesn't support deleting directly using joins and subqueries.
        // MARIADB  : Current version requires another subquery "SELECT latestResponses.id FROM" when querying and deleting from the same table.
        //            DELETE clause can't have an alias, therefore additional subquery levels are required to link records.
        @NamedNativeQuery(name = OcspResponseData.DELETE_OLD_OCSP_DATA_BY_CAID,
                          query = "DELETE FROM OcspResponseData " +
                                  "WHERE producedAt < :cutoffTime " +
                                  "AND cAId = :caId  " +
                                  "AND id NOT IN ( " +
                                  "    SELECT latestResponses.id FROM ( " +
                                  "        SELECT ocsp.* FROM OcspResponseData ocsp " +
                                  "        INNER JOIN ( " +
                                  "            SELECT serialNumber, MAX(producedAt) as maximumProducedAt FROM OcspResponseData " +
                                  "            WHERE producedAt < :cutoffTime " +
                                  "            GROUP BY serialNumber " +
                                  "        ) maxProducedAtTable " +
                                  "        ON ocsp.serialNumber = maxProducedAtTable.serialNumber AND ocsp.producedAt = maxProducedAtTable.maximumProducedAt " +
                                  "        WHERE cAId = :caId " +
                                  "    ) latestResponses " +
                                  ")"),
        @NamedNativeQuery(name = OcspResponseData.DELETE_OLD_OCSP_DATA,
                          query = "DELETE FROM OcspResponseData " +
                                  "WHERE producedAt < :cutoffTime " +
                                  "AND id NOT IN ( " +
                                  "    SELECT latestResponses.id FROM ( " +
                                  "        SELECT ocsp.id FROM OcspResponseData ocsp " +
                                  "        INNER JOIN ( " +
                                  "            SELECT serialNumber, MAX(producedAt) as maximumProducedAt FROM OcspResponseData " +
                                  "            WHERE producedAt < :cutoffTime " +
                                  "            GROUP BY serialNumber " +
                                  "        ) maxProducedAtTable " +
                                  "        ON ocsp.serialNumber = maxProducedAtTable.serialNumber AND ocsp.producedAt = maxProducedAtTable.maximumProducedAt " +
                                  "    ) latestResponses " +
                                  ")"),
})
@SqlResultSetMapping(
        name = "OcspResponseData",
        classes = @ConstructorResult(
                targetClass = OcspResponseData.class,
                columns = {
                        @ColumnResult(name = "id", type = String.class),
                        @ColumnResult(name = "cAId", type = Integer.class),
                        @ColumnResult(name = "serialNumber", type = String.class),
                        @ColumnResult(name = "producedAt", type = long.class),
                        @ColumnResult(name = "nextUpdate", type = Long.class),
                        @ColumnResult(name = "ocspResponse", type = byte[].class),
                }
        )
)
public class OcspResponseData extends ProtectedData implements Serializable {

    public static final String FIND_EXPIRING_OCPS_DATA_BY_CAID = "OcspResponseData.findExpiringOcpsDataByCaId";
    public static final String DELETE_OLD_OCSP_DATA_BY_CAID = "OcspResponseData.deleteOldOcspDataByCaId";
    public static final String DELETE_OLD_OCSP_DATA = "OcspResponseData.deleteOldOcspData";

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(OcspResponseData.class);

    private static final int LATEST_PROTECT_VERSON = 1;

    private String id; // Randomly generated primary key
    private Integer caId;
    private String serialNumber;
    private long producedAt;
    private Long nextUpdate;
    private byte[] ocspResponse;
    private int rowVersion = 0;
    private String rowProtection;

    public OcspResponseData() {
    }

    public OcspResponseData(final String id, final Integer caId, final String serialNumber, final long producedAt, final Long nextUpdate,
            final byte[] ocspResponse) {
        this.id = id;
        this.caId = caId;
        this.serialNumber = serialNumber;
        this.producedAt = producedAt;
        this.nextUpdate = nextUpdate;
        this.ocspResponse = ocspResponse;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public Integer getCaId() {
        return caId;
    }

    public void setCaId(final Integer caId) {
        this.caId = caId;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public long getProducedAt() {
        return this.producedAt;
    }

    public void setProducedAt(final long producedAt) {
        this.producedAt = producedAt;
    }

    public Long getNextUpdate() {
        return this.nextUpdate;
    }

    public void setNextUpdate(final Long nextUpdate) {
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
        protectedStringBuilder.append(getCaId()).append(getSerialNumber()).append(getProducedAt()).append(getNextUpdate()).append(getOcspResponse());
        if (log.isDebugEnabled() && protectedStringBuilder.length() > 8000) {
            // Some profiling
            log.debug("OcspResponseData.getProtectString gives size: " + protectedStringBuilder.length());
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
        return new ProtectionStringBuilder().append(getCaId()).append(getSerialNumber()).toString();
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
