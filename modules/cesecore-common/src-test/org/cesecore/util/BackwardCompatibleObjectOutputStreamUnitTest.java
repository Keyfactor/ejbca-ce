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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

import org.junit.Test;

/**
 * Test of BackwardCompatibleObjectOutputStream
 */
public class BackwardCompatibleObjectOutputStreamUnitTest {

    private static final int TEST_VALUE = 123456;

    @Test
    public void renamedClassSerialization() throws IOException, ClassNotFoundException {
        final SerializedClassNewName newIncompatibleNameObj = new SerializedClassNewName();
        newIncompatibleNameObj.value = TEST_VALUE;

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final BackwardCompatibleObjectOutputStream oos = BackwardCompatibleObjectOutputStream.create(baos)) {
            oos.setRenamedClasses(MapTools.unmodifiableMap(SerializedClassNewName.class.getName(), SerializedClassOriginalName.class.getName()));
            oos.writeObject(newIncompatibleNameObj);
        }

        final ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        try (final ObjectInputStream ois = new ObjectInputStream(bais)) {
            final Object obj = ois.readObject();
            assertEquals("Objects should have the compatible class.", SerializedClassOriginalName.class, obj.getClass());
            assertEquals("Value in object should have been deserialized.", TEST_VALUE, ((SerializedClassOriginalName)obj).value);
        }
    }
}