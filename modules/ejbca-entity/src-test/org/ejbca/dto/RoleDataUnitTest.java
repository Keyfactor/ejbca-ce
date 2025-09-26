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

import org.cesecore.dto.RoleDataDtoBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class RoleDataUnitTest {




    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(
                new Object[]{null, null},
                new Object[]{"", null},
                new Object[]{"something", "something"},
                new Object[]{"  something ", "something"},
                new Object[]{"  something with space inside ", "something with space inside"});
    }

    private final String recordNameSpace;
    private final String beanNameSpace;

    public RoleDataUnitTest(final String recordNameSpace, final String beanNameSpace) {
        this.recordNameSpace = recordNameSpace;
        this.beanNameSpace = beanNameSpace;
    }

    @Test
    public void verifyBeanNameSpace() {
        // Given
        final var roleData = new RoleDataDtoBuilder().setNameSpace(recordNameSpace).build();

        // When
        final var bean = new RoleData();
        bean.init(roleData);

        // Then
        assertEquals(beanNameSpace, bean.getNameSpace());
    }

}
