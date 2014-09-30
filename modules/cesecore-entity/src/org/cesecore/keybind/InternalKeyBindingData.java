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

package org.cesecore.keybind;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;

/**
 * Database representation of an InternalKeyBinding.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "InternalKeyBindingData")
public class InternalKeyBindingData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(InternalKeyBindingData.class);

    private int id;                 // Internal and static over time representation when referencing this object
    private String name;            // A human friendly representation of this object
    private String status;          // The status as a String constant of InternalKeyBindingStatus
    private String keyBindingType;  // Mapped to implementation class
    private String certificateId;   // Reference to a Certificate currently in use by the implementation
    private int cryptoTokenId;      // Reference to a CryptoToken currently in use by the implementation
    private String keyPairAlias;    // Reference to an alias in the CryptoToken currently in use by the implementation
    private String rawData;         // Raw data like a with implementation specific details and configuration
    private long lastUpdate = 0;    // Last update to database, Unix epoch milliseconds
    private int rowVersion = 0;     // JPA Optimistic locking requirement
    private String rowProtection;   // Row integrity protection

    public InternalKeyBindingData(final int id, final String name, final InternalKeyBindingStatus status, final String keyBindingType, final String certificateId,
            final int cryptoTokenId, final String keyPairAlias, final LinkedHashMap<Object, Object> dataMap) {
        setId(id);
        setName(name);
        setStatusEnum(status);
        setKeyBindingType(keyBindingType);
        if (certificateId != null) {
            setCertificateId(certificateId.toLowerCase(Locale.ENGLISH));            
        } else {
            setCertificateId(null);
        }
        setCryptoTokenId(cryptoTokenId);
        setKeyPairAlias(keyPairAlias);
        setDataMap(dataMap);
        setLastUpdate(System.currentTimeMillis());
    }

    public InternalKeyBindingData() {}

    // @Id @Column
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    // @Column
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    // @Column
    /** Use getStatusEnum() instead */
    public String getStatus() { return status; }
    /** Use setStatusEnum(..) instead */
    public void setStatus(String status) { this.status = status; }

    // @Column
    public String getKeyBindingType() { return keyBindingType; }
    public void setKeyBindingType(String keyBindingType) { this.keyBindingType = keyBindingType; }

    // @Column
    public String getCertificateId() { return certificateId; }
    public void setCertificateId(String certificateId) { 
        if (certificateId != null) {
            this.certificateId = certificateId.toLowerCase(Locale.ENGLISH);
        } else {
            this.certificateId = null;
        }
    }
    // @Column
    public int getCryptoTokenId() { return cryptoTokenId; }
    public void setCryptoTokenId(int cryptoTokenId) { this.cryptoTokenId = cryptoTokenId; }

    // @Column
    public String getKeyPairAlias() { return keyPairAlias; }
    public void setKeyPairAlias(String keyPairAlias) { this.keyPairAlias = keyPairAlias; }

    // @Column
    public long getLastUpdate() { return lastUpdate; }
    public void setLastUpdate(long lastUpdate) { this.lastUpdate = lastUpdate; }

    // @Column @Lob
    /** Should not be invoked directly. Use getDataMap() instead. */
    public String getRawData() { return rawData; }
    /** Should not be invoked directly. Use setDataMap(..) instead. */
    public void setRawData(String rawData) { this.rawData = rawData; }

    // @Version @Column
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

    // @Column @Lob
    @Override
    public String getRowProtection() { return rowProtection; }
    @Override
    public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }
    
    //
    // Start Database integrity protection methods
    //
    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(1024);
        // What is important to protect here is the data that we define
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getName()).append(getStatus()).append(getKeyBindingType());
        build.append(getCertificateId()).append(String.valueOf(getCryptoTokenId())).append(getKeyPairAlias());
        build.append(getRawData()).append(String.valueOf(getLastUpdate()));
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
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
        return String.valueOf(getId());
    }
    //
    // End Database integrity protection methods
    //
    
    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        try {
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getRawData().getBytes("UTF8")));
            final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
            return dataMap;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);  // No UTF8 would be real trouble
        }
    }

    @Transient
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        try {
            // We must base64 encode string for UTF safety
            final LinkedHashMap<?, ?> a = new Base64PutHashMap();
            a.putAll((LinkedHashMap)dataMap);
            final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();
            final String data = baos.toString("UTF8");
            setRawData(data);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    
    @Transient
    public InternalKeyBindingStatus getStatusEnum() {
        return InternalKeyBindingStatus.valueOf(getStatus());
    }
    @Transient
    public void setStatusEnum(InternalKeyBindingStatus status) {
        setStatus(status.name());
    }
}
