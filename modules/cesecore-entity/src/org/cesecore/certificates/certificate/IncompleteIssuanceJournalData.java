/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

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
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;

/**
 * Journal table of certificates that have been published, but where issuance has not succeeded.
 * This table is only used for certificates with CT or direct publishing enabled, and entries
 * are deleted as soon as certificates are successfully issued (or processed by the IncompleteIssuanceServiceWorker)
 */
@Entity
@Table(name = "IncompleteIssuanceJournalData")
public class IncompleteIssuanceJournalData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final int LATEST_PROTECT_VERSON = 1;

    private static final Logger log = Logger.getLogger(IncompleteIssuanceJournalData.class);

    // We merge the serial number and CA ID, because primary keys with a single column have more
    // consistent and reliable behavior in different database softwares, than primary keys with multiple columns
    private String serialNumberAndCaId;
    private long startTime;
    private String rawData;
    private int rowVersion;
    private String rowProtection;

    private transient String serialNumber;
    private transient int caId;

    public IncompleteIssuanceJournalData() { }

    public IncompleteIssuanceJournalData(final int caId, final BigInteger serialNumber, final String rawData, final Date startTime) {
        this.serialNumberAndCaId = makePrimaryKey(caId, serialNumber);
        if (serialNumberAndCaId.length() > 250) { // very unlikely to happen in practice, but better be safe
            throw new IllegalArgumentException("Serial number + CA ID string is too long");
        }
        this.rawData = rawData;
        this.startTime = startTime.getTime();
    }

    public IncompleteIssuanceJournalData(final IncompletelyIssuedCertificateInfo info) {
        this(info.getCaId(), info.getSerialNumber(), null, info.getStartTime());
        setDataMap(info.getRawData());
    }

    public static String makePrimaryKey(final int caId, final BigInteger serialNumber) {
        return serialNumber.toString(16) + ";" + caId;
    }


    public String getSerialNumberAndCaId() {
        return serialNumberAndCaId;
    }

    public void setSerialNumberAndCaId(final String serialNumberAndCaId) {
        this.serialNumberAndCaId = serialNumberAndCaId;
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public String getRawData() {
        return rawData;
    }

    public void setRawData(String rawData) {
        this.rawData = rawData;
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
        return new ProtectionStringBuilder().append(getSerialNumberAndCaId())
                .append(getStartTime()).toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return LATEST_PROTECT_VERSON;
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

    @Override
    @Transient
    protected String getRowId() {
        return new ProtectionStringBuilder().append(getSerialNumberAndCaId()).toString();
    }

    //
    // End Database integrity protection methods
    //

    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(getRawData().getBytes(StandardCharsets.UTF_8)));) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?, ?>) decoder.readObject());
        } catch (IOException e) {
            final String msg = "Failed to parse IncompleteIssuanceJournalData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + getRawData());
            }
            throw new IllegalStateException(msg, e);
        }
    }

    @Transient
    public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        // We must base64 encode string for UTF-8 safety
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos);) {
            encoder.writeObject(new Base64PutHashMap(dataMap));
        }
        setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
    }

    @Transient
    public BigInteger getSerialNumber() {
        decodeSerialNumberAndCaId();
        return new BigInteger(serialNumber, 16);
    }

    @Transient
    public int getCaId() {
        decodeSerialNumberAndCaId();
        return caId;
    }

    private void decodeSerialNumberAndCaId() {
        if (serialNumber == null) {
            final String[] pieces = serialNumberAndCaId.split(";", 2);
            caId = Integer.valueOf(pieces[1]);
            serialNumber = pieces[0];
        }
    }

}
