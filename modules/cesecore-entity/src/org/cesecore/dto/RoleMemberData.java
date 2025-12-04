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

public interface RoleMemberData extends Dto<Integer>, Comparable<RoleMemberData> {

    Integer primaryKey();
    default Integer getPrimaryKey() { return primaryKey(); } // Needed for ConfigDump

    String tokenType();
    default String getTokenType() { return tokenType(); } // Needed for ConfigDump

    int tokenIssuerId();
    default int getTokenIssuerId() { return tokenIssuerId(); } // Needed for ConfigDump

    int tokenProviderId();
    default int getTokenProviderId() { return tokenProviderId(); } // Needed for ConfigDump

    int tokenMatchKey();
    default int getTokenMatchKey() { return tokenMatchKey(); } // Needed for ConfigDump

    int tokenMatchOperator();
    default int getTokenMatchOperator() { return tokenMatchOperator(); } // Needed for ConfigDump

    String tokenMatchValue();
    default String getTokenMatchValue() { return tokenMatchValue(); } // Needed for ConfigDump

    int roleId();
    default int getRoleId() { return roleId(); } // Needed for ConfigDump

    String description();
    default String getDescription() { return description(); } // Needed for ConfigDump


    RoleMemberDataBuilder toBuilder();
    RoleMemberData withPrimaryKey(final Integer primaryKey);
    RoleMemberData withTokenType(final String tokenType);
    RoleMemberData withTokenIssuerId(final int tokenIssuerId);
    RoleMemberData withTokenProviderId(final int tokenProviderId);
    RoleMemberData withTokenMatchKey(final int tokenMatchKey);
    RoleMemberData withTokenMatchOperator(final int tokenMatchOperator);
    RoleMemberData withTokenMatchValue(final String tokenMatchValue);
    RoleMemberData withRoleId(final int roleId);
    RoleMemberData withDescription(final String description);

}
