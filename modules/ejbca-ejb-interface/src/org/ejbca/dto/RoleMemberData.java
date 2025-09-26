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

import org.cesecore.repository.dto.Dto;

public interface RoleMemberData extends Dto<Integer>, Comparable<RoleMemberData> {

    int ROLE_MEMBER_ID_UNASSIGNED = 0;
    int NO_ROLE = 0; // Role.ROLE_ID_UNASSIGNED;
    int NO_ISSUER = 0;
    int NO_PROVIDER = 0;

    Integer primaryKey();
    String tokenType();
    int tokenIssuerId();
    int tokenProviderId();
    int tokenMatchKey();
    int tokenMatchOperator();
    String tokenMatchValue();
    int roleId();
    String description();

    RoleMemberDataBean toBean();
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
