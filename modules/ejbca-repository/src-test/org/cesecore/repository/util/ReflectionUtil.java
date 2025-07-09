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

package org.cesecore.repository.util;

import org.junit.Assert;

import java.lang.reflect.Field;
import java.util.Objects;

public class ReflectionUtil {

    public static <T> T getFieldValue(Object instance, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field idMapField = instance.getClass().getDeclaredField(fieldName);
        idMapField.setAccessible(true);
        Object value = idMapField.get(instance);
        Assert.assertNotNull(value);
        return (T)value;
    }

    public static boolean containsValue(Object instance, Object value) {
        if (Objects.equals(instance, value)) {
            return true;
        }
        final var fields = instance.getClass().getDeclaredFields();
        for (final var field : fields) {
            field.setAccessible(true);
            try {
                if (Objects.equals(field.get(instance), value)) {
                    return true;
                }
            } catch (IllegalAccessException e) {
            }
        }
        return false;
    }

}
