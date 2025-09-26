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
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedDataImpl;
import org.cesecore.dbprotection.ProtectedDataIntegrityImpl;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.dto.RoleMemberData;
import org.cesecore.dto.RoleMemberDataRecord;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "RoleMemberData")
public final class RoleMemberDataBean implements Serializable, EntityManagerBean<RoleMemberData> {

    private static ProtectedDataImpl protectedDataImpl;

    static {
        protectedDataImpl = new ProtectedDataIntegrityImpl();
        protectedDataImpl.setTableName("RoleMemberData");
    }

    public static ProtectedDataImpl getProtectedDataImpl() {
        return protectedDataImpl;
    }

    public static void setProtectedDataImpl(final ProtectedDataImpl protectedDataImpl) {
        RoleMemberDataBean.protectedDataImpl = protectedDataImpl;
    }

    private Integer primaryKey;
    private String tokenType;
    private int tokenIssuerId;
    private int tokenProviderId;
    private int tokenMatchKey;
    private int tokenMatchOperator;
    private String tokenMatchValue;
    private int roleId;
    private String description;
    private Integer rowVersion;
    private String rowProtection;

    public RoleMemberDataBean() {
        rowVersion = 0;
    }

    @Id
    public Integer getPrimaryKey() {
       return this.primaryKey;
    }

    public void setPrimaryKey(Integer primaryKey) {
       this.primaryKey = primaryKey;
    }

    public String getTokenType() {
       return this.tokenType;
    }

    public void setTokenType(String tokenType) {
       this.tokenType = tokenType;
    }

    public int getTokenIssuerId() {
       return this.tokenIssuerId;
    }

    public void setTokenIssuerId(int tokenIssuerId) {
       this.tokenIssuerId = tokenIssuerId;
    }

    public int getTokenProviderId() {
       return this.tokenProviderId;
    }

    public void setTokenProviderId(int tokenProviderId) {
       this.tokenProviderId = tokenProviderId;
    }

    public int getTokenMatchKey() {
       return this.tokenMatchKey;
    }

    public void setTokenMatchKey(int tokenMatchKey) {
       this.tokenMatchKey = tokenMatchKey;
    }

    public int getTokenMatchOperator() {
       return this.tokenMatchOperator;
    }

    public void setTokenMatchOperator(int tokenMatchOperator) {
       this.tokenMatchOperator = tokenMatchOperator;
    }

    public String getTokenMatchValue() {
       return this.tokenMatchValue;
    }

    public void setTokenMatchValue(String tokenMatchValue) {
       this.tokenMatchValue = tokenMatchValue;
    }

    public int getRoleId() {
       return this.roleId;
    }

    public void setRoleId(int roleId) {
       this.roleId = roleId;
    }

    public String getDescription() {
       return this.description;
    }

    public void setDescription(String description) {
       this.description = description;
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

    @Override
    public RoleMemberData toDto() {
        return new RoleMemberDataRecord(
                    getPrimaryKey(),
                    getTokenType(),
                    getTokenIssuerId(),
                    getTokenProviderId(),
                    getTokenMatchKey(),
                    getTokenMatchOperator(),
                    getTokenMatchValue(),
                    getRoleId(),
                    getDescription());
    }

    @Override
    public void init(RoleMemberData dto) {
        setPrimaryKey(dto.primaryKey());
        setTokenType(dto.tokenType());
        setTokenIssuerId(dto.tokenIssuerId());
        setTokenProviderId(dto.tokenProviderId());
        setTokenMatchKey(dto.tokenMatchKey());
        setTokenMatchOperator(dto.tokenMatchOperator());
        setTokenMatchValue(dto.tokenMatchValue());
        setRoleId(dto.roleId());
        setDescription(dto.description());
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
        builder.append(getPrimaryKey());
        builder.append(getTokenType());
        builder.append(getTokenIssuerId());
        builder.append(getTokenProviderId());
        builder.append(getTokenMatchKey());
        builder.append(getTokenMatchOperator());
        builder.append(getTokenMatchValue());
        builder.append(getRoleId());
        builder.append(getDescription());
        return builder.toString();
    }

    @PrePersist
    @PreUpdate
    protected void protectData() throws DatabaseProtectionException {
        final var unProtectedData = getProtectString(getProtectVersion());
        final var protectedData = protectedDataImpl.getProtectedData(rowVersion, unProtectedData);
        if (protectedData != null) {
            setRowProtection(protectedData);
        }
    }

    @PostLoad
    protected void verifyData() throws DatabaseProtectionException {
        try {
            final var unProtectedData = getProtectString(getProtectVersion());
            protectedDataImpl.verifyData(unProtectedData, rowProtection, "PublisherDataBean", String.valueOf(primaryKey));
        } catch (final DatabaseProtectionException e) {
            protectedDataImpl.onDataVerificationError(e);
        }
    }

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
       stringBuilder.append("primaryKey: " + primaryKey + "\n");
       stringBuilder.append("tokenType: " + tokenType + "\n");
       stringBuilder.append("tokenIssuerId: " + tokenIssuerId + "\n");
       stringBuilder.append("tokenProviderId: " + tokenProviderId + "\n");
       stringBuilder.append("tokenMatchKey: " + tokenMatchKey + "\n");
       stringBuilder.append("tokenMatchOperator: " + tokenMatchOperator + "\n");
       stringBuilder.append("tokenMatchValue: " + tokenMatchValue + "\n");
       stringBuilder.append("roleId: " + roleId + "\n");
       stringBuilder.append("description: " + description + "\n");
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
       RoleMemberDataBean roleMemberDataBean = (RoleMemberDataBean) o;
       return
          Objects.equals(primaryKey, roleMemberDataBean.primaryKey) &&
          Objects.equals(tokenType, roleMemberDataBean.tokenType) &&
          Objects.equals(tokenIssuerId, roleMemberDataBean.tokenIssuerId) &&
          Objects.equals(tokenProviderId, roleMemberDataBean.tokenProviderId) &&
          Objects.equals(tokenMatchKey, roleMemberDataBean.tokenMatchKey) &&
          Objects.equals(tokenMatchOperator, roleMemberDataBean.tokenMatchOperator) &&
          Objects.equals(tokenMatchValue, roleMemberDataBean.tokenMatchValue) &&
          Objects.equals(roleId, roleMemberDataBean.roleId) &&
          Objects.equals(description, roleMemberDataBean.description) &&
          Objects.equals(rowVersion, roleMemberDataBean.rowVersion) &&
          Objects.equals(rowProtection, roleMemberDataBean.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
                 primaryKey,
                 tokenType,
                 tokenIssuerId,
                 tokenProviderId,
                 tokenMatchKey,
                 tokenMatchOperator,
                 tokenMatchValue,
                 roleId,
                 description,
                 rowVersion,
                 rowProtection);
    }

}
