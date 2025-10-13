/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.roles.AccessRulesHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class RoleDataMigrateUnitTest {

    private final PrevRole expectedPrevRole;
    private final RoleDataDto expectedRoleData;

    private static LinkedHashMap<String, Boolean> getNormalizedAccessRules(Map<String, Boolean> accessRules) {
        if (accessRules == null) {
            return null;
        }
        else {
            LinkedHashMap<String, Boolean> normalized = new LinkedHashMap<>(accessRules);
            AccessRulesHelper.normalizeResources(normalized);
            return normalized;
        }
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        final Integer[] styleIdArray = new Integer[] {
                null,
                0,
                100
        };
        final Map<String, Boolean>[] accessRulesArray = new Map[] {
                null,
                Map.of(),
                Map.of("A", true, "B", false)
        };
        final List<Object[]> argumentList = new ArrayList<>();
        for (Integer styleId : styleIdArray) {
            for (var accessRules : accessRulesArray) {
                argumentList.add(new Object[] { 10, "some name", "some namespace", styleId, getNormalizedAccessRules(accessRules) });
            }
        }
        return argumentList;
    }

    public RoleDataMigrateUnitTest(final int roleId, final String roleName, final String nameSpace, final Integer styleId, final LinkedHashMap<String, Boolean> accessRules) {
        this.expectedPrevRole = new PrevRole(nameSpace, roleName);
        this.expectedPrevRole.setRoleId(roleId);
        var builder = new RoleDataDtoBuilder()
                .setId(roleId)
                .setName(roleName)
                .setNameSpace(nameSpace);
        if (styleId != null) {
            this.expectedPrevRole.setStyleId(styleId);
            builder.setStyleId(styleId);
        }
        if (accessRules != null) {
            this.expectedPrevRole.setAccessRules(accessRules);
            builder.setAccessRules(accessRules);
        }
        this.expectedRoleData = builder.build();
    }

    @Test
    public void testUpgrade() {
        // Given
        var prevRoleData = new PrevRoleData(this.expectedPrevRole);

        // When
        var RoleData = new RoleData();
        RoleData.setId(prevRoleData.getId());
        RoleData.setRoleName(prevRoleData.getRoleName());
        RoleData.setNameSpace(prevRoleData.getNameSpace());
        RoleData.setRawData(prevRoleData.getRawData());
        var actual = RoleData.toDto();

        // Then
        String message = "Expected:\n" + expectedRoleData + "\nActual:\n" + actual;
        assertEquals(message, expectedRoleData, actual);
    }

    @Test
    public void testDowngrade() {
        // Given
        final var RoleData = new RoleData();
        RoleData.init(this.expectedRoleData);

        // When
        final PrevRoleData prevRolData = new PrevRoleData();
        prevRolData.setId(RoleData.getId());
        prevRolData.setRoleName(RoleData.getRoleName());
        prevRolData.setNameSpace(RoleData.getNameSpace());
        prevRolData.setRawData(RoleData.getRawData());
        final var actual = new PrevRole(prevRolData.getNameSpace(), prevRolData.getRoleName());
        actual.setRoleId(prevRolData.getId());
        actual.loadData(prevRolData.getDataMap());


        // Then
        assertEquals(this.expectedPrevRole, actual);
    }

}
