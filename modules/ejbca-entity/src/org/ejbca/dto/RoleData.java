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

package org.ejbca.dto;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectedDataImpl;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

@Entity
@Table(name = "RoleData")
public final class RoleData implements Serializable, EntityManagerBean<RoleDataDto> {

    public static final float LATEST_VERSION = 1;
    public static final String KEY_ACCESS_RULES = "accessRules";
    public static final String KEY_ASSOCIATED_CSS = "associatedCss";
    @Serial
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RoleData.class);

    private static ProtectedDataImpl protectedDataImpl;

    static {
        protectedDataImpl = ProtectedData.initializeProtectedDataImpl("RoleData");
    }

    // It is important that the names below match the ones in the database table RoleDataDto
    private Integer id;
    private String roleName;
    private String nameSpace;
    private String rawData;
    private Integer rowVersion;
    private String rowProtection;

    public RoleData() {
        rowVersion = 0;
    }

    @Id
    public Integer getId() {
       return this.id;
    }

    public void setId(Integer id) {
       this.id = id;
    }

    public String getRoleName() {
       return this.roleName;
    }

    public void setRoleName(String roleName) {
       this.roleName = roleName;
    }

    public String getNameSpace() {
       return this.nameSpace;
    }

    public void setNameSpace(String nameSpace) {
       this.nameSpace = nameSpace;
    }

    public String getRawData() {
       return rawData;
    }

    public void setRawData(String rawData) {
       this.rawData = rawData;
    }

    public int getRowVersion() {
        return this.rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    public String getRowProtection() {
        return this.rowProtection;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Transient
    @Override
    public int getProtectVersion() {
        return 1;
    }

    @Transient
    @Override
    public String getProtectString(final int version) {
        ProtectionStringBuilder builder = new ProtectionStringBuilder();
        builder.append(getId());
        builder.append(getRoleName());
        builder.append(getNameSpace());
        return builder.toString();
    }

    @PrePersist
    @PreUpdate
    private void protectData() throws DatabaseProtectionException {
        final var unProtectedData = getProtectString(getProtectVersion());
        final var protectedData = protectedDataImpl.getProtectedData(rowVersion, unProtectedData);
        if (protectedData != null) {
            setRowProtection(protectedData);
        }
    }

    // Direct copy of the previous org.cesecore.roles.RoleDataDto
    Base64GetHashMap getMapFromXml(final String xml) {
        if (xml == null) {
            return new Base64GetHashMap();
        }
        try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?, ?>)decoder.readObject());
        } catch (IOException e) {
            final String msg = "Failed to parse data map for role '" + roleName + "': " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + xml);
            }
            throw new IllegalStateException(msg, e);
        }
    }

    // Direct copy of the previous org.cesecore.roles.RoleDataDto
    String getXmlFromMap(final LinkedHashMap<Object, Object> dataMap) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)){
            // We must base64 encode string for UTF safety
            encoder.writeObject(new Base64PutHashMap(dataMap));
        }
        return baos.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void init(RoleDataDto roleData) {
        this.id = roleData.id();
        this.roleName = roleData.name();
        this.nameSpace = StringUtils.defaultIfEmpty(roleData.getNameSpace(), null);
        LinkedHashMap<Object, Object> map = new LinkedHashMap<>();
        map.put("version", LATEST_VERSION);
        map.put(KEY_ASSOCIATED_CSS, roleData.styleId());
        map.put(KEY_ACCESS_RULES, new LinkedHashMap<>(roleData.accessRules()));
        this.rawData = getXmlFromMap(map);
    }

    float getVersion(Map<String, Object> map) {
        Object versionObject = map.get(KEY_VERSION);
        return versionObject == null ? LATEST_VERSION : (Float)versionObject;
    }

    @Override
    public RoleDataDto toDto() {
        var map = getMapFromXml(rawData);
        float version = getVersion(map);
        if (version < LATEST_VERSION) {
            upgrade();
        }
        Object styleIdValue = map.get(KEY_ASSOCIATED_CSS);
        int styleId = styleIdValue == null ? 0 : (Integer) styleIdValue;
        Object mapValue = map.get(KEY_ACCESS_RULES);
        @SuppressWarnings("unchecked")
        Map<String, Boolean> accessRules = mapValue == null ?
                new HashMap<>() :
                (Map<String, Boolean>) mapValue;
        return new RoleDataDto(
                id,
                roleName,
                nameSpace,
                styleId,
                accessRules);
    }

    @PostLoad
    private void verifyData() throws DatabaseProtectionException {
        try {
            final var unProtectedData = getProtectString(getProtectVersion());
            protectedDataImpl.verifyData(unProtectedData, rowProtection, "PublisherDataBean", String.valueOf(id));
        } catch (final DatabaseProtectionException e) {
            protectedDataImpl.onDataVerificationError(e);
        }
    }

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
       stringBuilder.append("id: " + id + "\n");
       stringBuilder.append("roleName: " + roleName + "\n");
       stringBuilder.append("nameSpace: " + nameSpace + "\n");
       stringBuilder.append("data: \n");
       stringBuilder.append(rawData);
       stringBuilder.append("rowVersion: " + rowVersion + "\n");
       stringBuilder.append("rowProtection: " + rowProtection + "\n");
       return stringBuilder.toString();
    }

    @Override
    public boolean equals(Object o) {
       if (this == o) {
          return true;
       }
       if (o == null || getClass() != o.getClass()) {
          return false;
       }
       RoleData roleData = (RoleData) o;
       return
          Objects.equals(id, roleData.id) &&
          Objects.equals(roleName, roleData.roleName) &&
          Objects.equals(nameSpace, roleData.nameSpace) &&
          Objects.equals(rawData, roleData.rawData) &&
          Objects.equals(rowVersion, roleData.rowVersion) &&
          Objects.equals(rowProtection, roleData.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
                 id,
                 roleName,
                 nameSpace,
                 rawData,
                 rowVersion,
                 rowProtection);
    }

}
