/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.acme;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;


/**
 *
 * @version $Id$
 */

@Entity
@Table(name = "AcmeOrderData")
public class AcmeOrderData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    private String orderId;
    
    private String accountId;
    private String fingerprint;
    private String status;
    private String rawData;
    private int rowVersion = 0;
    private String rowProtection;

    public AcmeOrderData() {}

    public AcmeOrderData(final String orderId, final String accountId, final String fingerprint, final String status, final LinkedHashMap<Object,Object> dataMap) {
        this.orderId = orderId;
        this.accountId = accountId;
        this.fingerprint = fingerprint;
        this.status = status;
        setDataMap(dataMap);
    }
    
    public String getOrderId() {
        return orderId;
    }
    
    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }
    
    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }
    
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getRawData() {
        return rawData;
    }

    public void setRawData(String rawData) {
        this.rawData = rawData;
    }

    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object,Object> getDataMap() {
        try (final XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(getRawData().getBytes(StandardCharsets.UTF_8)));) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?,?>)decoder.readObject());
        }
    }

    @Transient
    public void setDataMap(final LinkedHashMap<Object,Object> dataMap) {
        // We must base64 encode string for UTF safety
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos);) {
            encoder.writeObject(new Base64PutHashMap(dataMap));
        }
        setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
    }
    
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

    
    public String getRowProtection() { return rowProtection; }
    
    public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    
    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking so we will not include that in the database protection
        return new ProtectionStringBuilder().append(getOrderId()).append(getAccountId()).append(getRawData()).toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
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
        return getAccountId();
    }

    //
    // End Database integrity protection methods
    //
}
