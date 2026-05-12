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
package org.ejbca.core.ejb.approval;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.other.company.approval.DummyNonAllowedSerializableClass;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ApprovalDataUnitTest {

    private static List<Object> getValidObjects() {
        return Arrays.asList(
                10,
                BigInteger.valueOf(10),
                "Some message");
    }

    private static List<Object> getNonValidObjects() {
        return List.of(
                new DummyNonAllowedSerializableClass()
        );
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        final var validObjects = getValidObjects();
        final var nonValidObjects = getNonValidObjects();
        final var allObjects = new ArrayList<Object[]>();
        for (var object : validObjects) {
            allObjects.add(new Object[]{ object, true });
        }
        for (var object : nonValidObjects) {
            allObjects.add(new Object[]{ object, false });
        }
        return allObjects;
    }

    private final ApprovalData approvalData;
    private final Object object;
    private final boolean isAllowed;

    public ApprovalDataUnitTest(final Object object, final boolean isAllowed) {
        this.approvalData = new ApprovalData();
        this.object = object;
        this.isAllowed = isAllowed;
    }

    InputStream getInputStream() throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (final ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(object);
        }
        final byte[] bytes = byteArrayOutputStream.toByteArray();
        return new ByteArrayInputStream(bytes);
    }

    @Before
    public void setUp() {
        ApprovalData.allowedClasses = new ArrayList<>(ApprovalData.allowedClasses);
        ApprovalData.allowedClasses.add(DummyAllowedSerializableClass.class);
        int n = ApprovalData.allowedSubclassPackagePrefixes.length;
        String[] allowedSubclassPackagePrefixes = new String[n+1];
        for (int i=0; i<n; i++) {
            allowedSubclassPackagePrefixes[i] = ApprovalData.allowedSubclassPackagePrefixes[i];
        }
        allowedSubclassPackagePrefixes[n] = DummyAllowedSerializableClass.class.getPackage().getName();
        ApprovalData.allowedSubclassPackagePrefixes = allowedSubclassPackagePrefixes;
    }

    @Test
    public void testReadObjectWithLookAhead() throws IOException, ClassNotFoundException {
        // Given
        final var inputStream = getInputStream();

        // When
        if (isAllowed) {
            var actual = approvalData.readObjectWithLookAhead(inputStream);

            // Then
            assertEquals(object, actual);
        }
        else {
            try {
                var actual = approvalData.readObjectWithLookAhead(inputStream);
                Assert.fail("Expected SecurityException, but got the value: " + actual+ " ("+actual.getClass().getName()+")");
            }
            catch (SecurityException e) {
            }
        }
    }

}
