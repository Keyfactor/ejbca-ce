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
package org.cesecore.dto;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class RoleDataDtoUnitTest {

    private byte[] getBytes(final RoleDataDto roleDataDto) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(roleDataDto);
            return baos.toByteArray();
        }
    }

    private RoleDataDto getRoleDataRecord(final byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (RoleDataDto)ois.readObject();
        }
    }

    @Test
    public void testSerializeAndDeserialize() throws Exception {
        // Given
        RoleDataDto expected = new RoleDataDto(1, "someName", "someNameSpace", 10, Map.of("A", true, "B", false));

        // When
        var bytes = getBytes(expected);
        var actual = getRoleDataRecord(bytes);

        // Then
        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

}
