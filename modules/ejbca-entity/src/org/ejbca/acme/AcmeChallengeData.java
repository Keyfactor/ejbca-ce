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
package org.ejbca.acme;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;

/**
 *
 */
//@Entity
//@Table(name = "AcmeChallengeData")
public class AcmeChallengeData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AcmeChallengeData.class);

    private String challengeId;
    private String authorizationId;
    private String type;
    private String rawData;
    private int rowVersion = 0;
    private String rowProtection;


    public AcmeChallengeData() {
    }

    public AcmeChallengeData(final String challengeId, final String authorizationId, final String type, final LinkedHashMap<Object,Object> dataMap) {
        setChallengeId(challengeId);
        setAuthorizationId(authorizationId);
        setType(type);
        setDataMap(dataMap);
    }

    //@Column
    public String getChallengeId() {
        return challengeId;
    }
    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    //@Column
    public String getAuthorizationId() { return authorizationId; }
    public void setAuthorizationId(String authorizationId) { this.authorizationId = authorizationId; }

    //@Column
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }

    //@Column @Lob
    public String getRawData() { return rawData; }
    public void setRawData(String rawData) { this.rawData = rawData; }


    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object,Object> getDataMap() {
        try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(getRawData().getBytes(StandardCharsets.UTF_8)));) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?,?>)decoder.readObject());
        } catch (IOException e) {
            final String msg = "Failed to parse AcmeChallengeData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + getRawData());
            }
            throw new IllegalStateException(msg, e);
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

    //@Version @Column
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

    //@Column @Lob
    @Override
    public String getRowProtection() { return rowProtection; }
    @Override
    public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking so we will not include that in the database protection
        return new ProtectionStringBuilder().append(getChallengeId()).append(getAuthorizationId()).append(getType()).append(getRawData()).toString();
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
        return getChallengeId();
    }

    //
    // End Database integrity protection methods
    //
}
