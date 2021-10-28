/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import org.cesecore.util.ui.DynamicUiProperty;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;

public class SafeObjectInputStreamTest {

    private ByteArrayInputStream serialize(final Object... objects) throws IOException {
        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            try (final ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
                for (final Object object : objects) {
                    objectOutputStream.writeObject(object);
                }
            }
            return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        }
    }

    @Test(expected = SecurityException.class)
    public void testDeserialisationWithNothingAllowed() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new HashMap<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingNothing().build(byteStream)) {
            safeObjectInputStream.readObject();
        }
    }

    @Test(expected = SecurityException.class)
    public void testDeserialisationOfNonWhitelistedClass() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new LinkedList<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingNothing()
                .allowClass(ArrayList.class)
                .build(byteStream)) {
            safeObjectInputStream.readObject();
        }
    }

    @Test(expected = SecurityException.class)
    public void testDeserialisationOfClassFromNonWhitelistedPackage() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new LinkedList<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingNothing()
                .allowPackage("java.security")
                .build(byteStream)) {
            safeObjectInputStream.readObject();
        }
    }

    @Test
    public void testDeserialisationOfSafeDefaults() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new HashMap<>(), new DynamicUiProperty<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingSafeClasses().build(byteStream)) {
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
        }
    }

    @Test
    public void testDeserialisationOfAllowedClass() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new HashMap<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingNothing()
                .allowClass(HashMap.class)
                .allowingNumberOfObjects(1)
                .build(byteStream)) {
            safeObjectInputStream.readObject();
        }
    }

    @Test(expected = SecurityException.class)
    public void testDeserialisationOfTooManyClasses() throws Exception {
        final ByteArrayInputStream byteStream = serialize(new HashMap<>(), new LinkedHashMap<>());
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingSafeClasses()
                .allowingNumberOfObjects(1)
                .build(byteStream)) {
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
        }
    }

    @Test
    public void testDeserialisationOfPrimitives() throws Exception {
        final ByteArrayInputStream byteStream = serialize(
                13.37f,
                13.37,
                1,
                1L,
                new char[] { '1', '3', '3', '7'},
                new char[][] {{'a'}, {'b'}},
                'g',
                "some string");
        try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingSafeClasses()
                .build(byteStream)) {
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
            safeObjectInputStream.readObject();
        }
    }
}
