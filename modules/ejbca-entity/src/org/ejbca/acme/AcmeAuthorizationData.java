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

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
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
import org.ejbca.core.protocol.acme.AcmeAuthorization;

/**
 * @version $Id$
 */
@Entity
@Table(name = "AcmeAuthorizationData")
public class AcmeAuthorizationData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AcmeAuthorizationData.class);
    
    private String authorizationId;
    private String identifier;
    private String identifierType;
    private long expires;
    private String status;
    private String orderId;
    private String accountId;
    private String rawData;
    private int rowVersion = 0;
    private String rowProtection;

    public AcmeAuthorizationData() {
    }
            
    public AcmeAuthorizationData(final String authorizationId, final String orderId, final String accountId, final LinkedHashMap<Object, Object> dataMap) {
        setAuthorizationId(authorizationId);
        setOrderId(orderId);
        setAccountId(accountId);
        setDataMap(dataMap);
    }
    
    public AcmeAuthorizationData(final AcmeAuthorization authorization) {    	
    	this(authorization.getAuthorizationId(), authorization.getOrderId(), authorization.getAccountId(), authorization.getRawData());
        setIdentifier(authorization.getAcmeIdentifier().getValue());
        setIdentifierType(authorization.getAcmeIdentifier().getType());
        setExpires(authorization.getExpires());
        setStatus(authorization.getStatus().getJsonValue());        
    }

    //@Column
    public String getAuthorizationId() {
        return authorizationId;
    }
    public void setAuthorizationId(String authorizationId) {
        this.authorizationId = authorizationId;
    }
    
    //@Column
    public String getIdentifier() {
        return identifier;
    }
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    //@Column
    public String getIdentifierType() {
        return identifierType;
    }
    public void setIdentifierType(String identifierType) {
        this.identifierType = identifierType;
    }

    //@Column
    public long getExpires() {
        return expires;
    }
    public void setExpires(long expires) {
        this.expires = expires;
    }

    //@Column
    public String getStatus() {
        return status;
    }
    public void setStatus(String status) {
        this.status = status;
    }

    //@Column
    public String getOrderId() {
        return orderId;
    }
    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    //@Column
    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    //@Column @Lob
    public String getRawData() {
        return rawData;
    }
    public void setRawData(String rawData) {
        this.rawData = rawData;
    }

    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(getRawData().getBytes(StandardCharsets.UTF_8)));) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?, ?>) decoder.readObject());
        } catch (IOException e) {
            final String msg = "Failed to parse AcmeAuthorizationData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + getRawData());
            }
            throw new IllegalStateException(msg, e);
        }
    }

    @Transient
    public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        // We must base64 encode string for UTF safety
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos);) {
            encoder.writeObject(new Base64PutHashMap(dataMap));
        }
        setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
    }

    //@Version @Column
    public int getRowVersion() {
        return rowVersion;
    }
    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }

    //@Column @Lob
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
        return new ProtectionStringBuilder().append(getAuthorizationId()).append(getOrderId()).append(getRawData()).toString();
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
        return getAuthorizationId();
    }

    //
    // End Database integrity protection methods
    //
}
