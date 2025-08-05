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


public class RoleMemberDataBuilder {

    private Integer primaryKey;
    private String tokenType;
    private int tokenIssuerId;
    private int tokenProviderId;
    private int tokenMatchKey;
    private int tokenMatchOperator;
    private String tokenMatchValue;
    private int roleId;
    private String description;

    public RoleMemberDataBuilder() {
    }

    public RoleMemberDataBuilder(RoleMemberData roleMemberData) {
        setPrimaryKey(roleMemberData.primaryKey());
        setTokenType(roleMemberData.tokenType());
        setTokenIssuerId(roleMemberData.tokenIssuerId());
        setTokenProviderId(roleMemberData.tokenProviderId());
        setTokenMatchKey(roleMemberData.tokenMatchKey());
        setTokenMatchOperator(roleMemberData.tokenMatchOperator());
        setTokenMatchValue(roleMemberData.tokenMatchValue());
        setRoleId(roleMemberData.roleId());
        setDescription(roleMemberData.description());
    }

    public RoleMemberDataBuilder setPrimaryKey(final Integer primaryKey) {
        this.primaryKey = primaryKey;
        return this;
    }

    public RoleMemberDataBuilder setTokenType(final String tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    public RoleMemberDataBuilder setTokenIssuerId(final int tokenIssuerId) {
        this.tokenIssuerId = tokenIssuerId;
        return this;
    }

    public RoleMemberDataBuilder setTokenProviderId(final int tokenProviderId) {
        this.tokenProviderId = tokenProviderId;
        return this;
    }

    public RoleMemberDataBuilder setTokenMatchKey(final int tokenMatchKey) {
        this.tokenMatchKey = tokenMatchKey;
        return this;
    }

    public RoleMemberDataBuilder setTokenMatchOperator(final int tokenMatchOperator) {
        this.tokenMatchOperator = tokenMatchOperator;
        return this;
    }

    public RoleMemberDataBuilder setTokenMatchValue(final String tokenMatchValue) {
        this.tokenMatchValue = tokenMatchValue;
        return this;
    }

    public RoleMemberDataBuilder setRoleId(final int roleId) {
        this.roleId = roleId;
        return this;
    }

    public RoleMemberDataBuilder setDescription(final String description) {
        this.description = description;
        return this;
    }

    public RoleMemberData build() {
        return new RoleMemberDataRecord(primaryKey,
                           tokenType,
                           tokenIssuerId,
                           tokenProviderId,
                           tokenMatchKey,
                           tokenMatchOperator,
                           tokenMatchValue,
                           roleId,
                           description);

    }
}
