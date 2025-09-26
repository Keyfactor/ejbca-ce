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

package org.cesecore.dto;

import org.cesecore.util.CompareUtil;

public record RoleMemberDataRecord(
                       Integer primaryKey,
                       String tokenType,
                       int tokenIssuerId,
                       int tokenProviderId,
                       int tokenMatchKey,
                       int tokenMatchOperator,
                       String tokenMatchValue,
                       int roleId,
                       String description) implements RoleMemberData {

    @Override
    public Integer id() {
        return primaryKey;
    }


    @Override
    public RoleMemberDataBuilder toBuilder() {
        return new RoleMemberDataBuilder(this);
    }

    @Override
    public RoleMemberData withId(final Integer id) {
        return withPrimaryKey(id);
    }

    @Override
    public RoleMemberData withPrimaryKey(final Integer primaryKey) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenType(final String tokenType) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenIssuerId(final int tokenIssuerId) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenProviderId(final int tokenProviderId) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenMatchKey(final int tokenMatchKey) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenMatchOperator(final int tokenMatchOperator) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withTokenMatchValue(final String tokenMatchValue) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withRoleId(final int roleId) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public RoleMemberData withDescription(final String description) {
        return new RoleMemberDataRecord(
                primaryKey,
                tokenType,
                tokenIssuerId,
                tokenProviderId,
                tokenMatchKey,
                tokenMatchOperator,
                tokenMatchValue,
                roleId,
                description);
    }

    @Override
    public int compareTo(final RoleMemberData roleMemberData) {
        int c;
        c = CompareUtil.compare(this.primaryKey, roleMemberData.primaryKey());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenType, roleMemberData.tokenType());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenIssuerId, roleMemberData.tokenIssuerId());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenProviderId, roleMemberData.tokenProviderId());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenMatchKey, roleMemberData.tokenMatchKey());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenMatchOperator, roleMemberData.tokenMatchOperator());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.tokenMatchValue, roleMemberData.tokenMatchValue());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.roleId, roleMemberData.roleId());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.description, roleMemberData.description());
        if (c != 0) {
            return c;
        }
        return 0;
    }

}
