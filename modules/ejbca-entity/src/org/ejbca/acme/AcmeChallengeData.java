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

import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
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
//@Entity
//@Table(name = "AcmeChallengeData")
public class AcmeChallengeData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

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
