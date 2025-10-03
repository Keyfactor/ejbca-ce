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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class RoleDataDtoBuilder {

    private Integer id;
    private String name;
    private String nameSpace;
    private int styleId;
    private Map<String, Boolean> accessRules;

    public RoleDataDtoBuilder() {
        accessRules = new HashMap<>();
    }

    public RoleDataDtoBuilder(RoleDataDto roleData) {
        if (roleData == null) {
            this.accessRules = new HashMap<>();
        }
        else {
            this.id = roleData.id();
            this.name = roleData.name();
            this.nameSpace = roleData.nameSpace();
            this.styleId = roleData.styleId();
            this.accessRules = new HashMap<>(roleData.accessRules());
        }
    }

    public Integer getId() {
        return id;
    }

    public RoleDataDtoBuilder setId(final Integer id) {
        this.id = id;
        return this;
    }

    public String getName() {
        return name;
    }

    public RoleDataDtoBuilder setName(final String name) {
        this.name = name;
        return this;
    }

    public String getNameSpace() {
        return nameSpace;
    }

    public RoleDataDtoBuilder setNameSpace(final String nameSpace) {
        this.nameSpace = nameSpace;
        return this;
    }

    public Integer getStyleId() {
        return styleId;
    }

    public RoleDataDtoBuilder setStyleId(int styleId) {
        this.styleId = styleId;
        return this;
    }

    public Map<String, Boolean> getAccessRules() {
        return accessRules;
    }

    public RoleDataDtoBuilder setAccessRules(Map<String, Boolean> accessRules) {
        this.accessRules = accessRules;
        return this;
    }

    public RoleDataDto build() {
        return new RoleDataDto(id,
                           name,
                           nameSpace,
                           styleId,
                           accessRules);
    }

    @Override
    public String toString() {
        return build().toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        RoleDataDtoBuilder other = (RoleDataDtoBuilder) obj;
        return Objects.equals(this.id, other.id) &&
                Objects.equals(this.name, other.name) &&
                Objects.equals(this.nameSpace, other.nameSpace) &&
                Objects.equals(this.styleId, other.styleId) &&
                Objects.equals(this.accessRules, other.accessRules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, nameSpace, styleId, accessRules);
    }

}
