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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class RoleDataDtoNameSpaceUnitTest {

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(
                new Object[]{null, ""},
                new Object[]{"", ""},
                new Object[]{"something", "something"},
                new Object[]{"  something ", "something"},
                new Object[]{"  something with space inside ", "something with space inside"});
    }

    private final String beanNameSpace;
    private final String recordNameSpace;

    public RoleDataDtoNameSpaceUnitTest(final String beanNameSpace, final String recordNameSpace) {
        this.beanNameSpace = beanNameSpace;
        this.recordNameSpace = recordNameSpace;
    }

    @Test
    public void verifyRecordNameSpace() {
        // Given
        final var bean = new RoleData();
        bean.setNameSpace(beanNameSpace);

        // When
        final var dto = bean.toDto();

        // Then
        assertEquals(recordNameSpace, dto.getNameSpace());
    }

}
