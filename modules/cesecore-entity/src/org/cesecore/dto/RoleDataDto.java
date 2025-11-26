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

import org.apache.commons.lang3.StringUtils;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.util.CompareUtil;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

public record RoleDataDto(
                       Integer id,
                       String name,
                       String nameSpace,
                       int styleId,
                       Map<String, Boolean> accessRules) implements Dto<Integer>, Serializable, Comparable<RoleDataDto> {

    @Serial
    private static final long serialVersionUID = 0L;

    public static final int ROLE_ID_UNASSIGNED = 0;
    public static final boolean STATE_ALLOW = true;
    public static final boolean STATE_DENY = false;

    private static Map<String, Boolean> getNormalizedAccessRules(final Map<String, Boolean> accessRules) {
        Map<String, Boolean> normalizedAccessRules = new LinkedHashMap<>(accessRules);
        AccessRulesHelper.normalizeResources(normalizedAccessRules);
        return new LinkedHashMap<>(new TreeMap<>(normalizedAccessRules));
    }

    public RoleDataDto(
            Integer id,
            String name,
            String nameSpace,
            int styleId,
            Map<String, Boolean> accessRules) {
        this.id = id == null ?
                RoleDataDto.ROLE_ID_UNASSIGNED :
                id;
        this.name = StringUtils.isEmpty(name) ? "" : name.trim();
        this.nameSpace = StringUtils.isEmpty(nameSpace) ? "" : nameSpace.trim();
        this.styleId = styleId;
        this.accessRules = accessRules == null ?
                Map.of() :
                Collections.unmodifiableMap(getNormalizedAccessRules(accessRules));
    }

    @Override
    public Integer id() {
        return id;
    }

    // Needed for ConfigDump
    public Integer getId() {
        return id();
    }

    // Needed for ConfigDump
    public String getName() {
        return name();
    }

    // Needed for ConfigDump
    public String getNameSpace() {
        return nameSpace();
    }

    public boolean isIdUnassigned() {
        return id == RoleDataDto.ROLE_ID_UNASSIGNED;
    }

    public String[] indexNames() {
        return new String[] { "nameSpace", "name" };
    }

    public Object[] indexValues() {
        return new Object[] { nameSpace, name };
    }

    public String fullName() {
        return (nameSpace + " " + name).trim();
    }

    public String getFullName() {
        return fullName();
    }

    public int getStyleId() {
        return styleId();
    }

    // Needed for ConfigDump
    public Map<String, Boolean> getAccessRules() {
        return accessRules();
    }

    public RoleDataDtoBuilder toBuilder() {
        return new RoleDataDtoBuilder(this);
    }

    public RoleDataDto withId(final Integer id) {
        return new RoleDataDto(
                id,
                name,
                nameSpace,
                styleId,
                accessRules);
    }

    public RoleDataDto withName(final String name) {
        return new RoleDataDto(
                id,
                name,
                nameSpace,
                styleId,
                accessRules);
    }

    public RoleDataDto withNameSpace(final String nameSpace) {
        return new RoleDataDto(
                id,
                name,
                nameSpace,
                styleId,
                accessRules);
    }

    public RoleDataDto withStyleId(final int styleId) {
        return new RoleDataDto(
                id,
                name,
                nameSpace,
                styleId,
                accessRules);
    }

    public RoleDataDto withAccessRules(final Map<String, Boolean> accessRules) {
        return new RoleDataDto(
                id,
                name,
                nameSpace,
                styleId,
                accessRules);
    }

    @Override
    public int compareTo(final RoleDataDto roleData) {
        int c;
        c = CompareUtil.compare(this.name, roleData.name());
        if (c != 0) {
            return c;
        }
        return CompareUtil.compare(this.nameSpace, roleData.nameSpace());
    }

    public void appendTo(final StringBuilder sb, final String prefix) {
        final int maxKeyLength = accessRules
                .keySet()
                .stream()
                .mapToInt(String::length)
                .max()
                .orElse(0);
        sb.append(prefix).append("id         = ").append(id).append('\n');
        sb.append(prefix).append("name       = ").append(name).append('\n');
        sb.append(prefix).append("nameSpace  = ").append(nameSpace).append('\n');
        sb.append(prefix).append("styleId    = ").append(styleId).append('\n');
        sb.append(prefix).append("accessRules").append('\n');
        final String format = "   %-" + maxKeyLength + "s = ";
        for (String key : accessRules.keySet()) {
            sb.append(prefix);
            sb.append(String.format(format, key));
            sb.append(accessRules.get(key)).append('\n');
        }
    }


    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        appendTo(sb, "");
        return sb.toString();
    }

}
