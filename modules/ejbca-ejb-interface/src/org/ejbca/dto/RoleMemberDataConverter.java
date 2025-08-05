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

import org.cesecore.repository.dto.Converter;

public final class RoleMemberDataConverter implements Converter<RoleMemberData, RoleMemberDataBean> {

    public RoleMemberDataBean toBean(RoleMemberData dto) {
        if (dto == null) {
            return null;
        }
        else {
            final var bean = new RoleMemberDataBean();
            bean.setPrimaryKey(dto.primaryKey());
            bean.setTokenType(dto.tokenType());
            bean.setTokenIssuerId(dto.tokenIssuerId());
            bean.setTokenProviderId(dto.tokenProviderId());
            bean.setTokenMatchKey(dto.tokenMatchKey());
            bean.setTokenMatchOperator(dto.tokenMatchOperator());
            bean.setTokenMatchValue(dto.tokenMatchValue());
            bean.setRoleId(dto.roleId());
            bean.setDescription(dto.description());
            return bean;
        }
    }

    public RoleMemberData toDto(RoleMemberDataBean bean) {
        if (bean == null) {
            return null;
        }
        else {
        return new RoleMemberDataRecord(bean.getPrimaryKey(),
                           bean.getTokenType(),
                           bean.getTokenIssuerId(),
                           bean.getTokenProviderId(),
                           bean.getTokenMatchKey(),
                           bean.getTokenMatchOperator(),
                           bean.getTokenMatchValue(),
                           bean.getRoleId(),
                           bean.getDescription());
        }
    }

}
