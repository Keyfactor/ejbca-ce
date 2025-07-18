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

package org.ejbca.repository.generator.util;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

public class CompareUtil {

    private CompareUtil() {
        // Prevent instantiation
    }

    protected static boolean doEquals(Iterator iteratorA, Iterator iteratorB) {
        while (iteratorA.hasNext() && iteratorB.hasNext()) {
            if (!equals(iteratorA.next(), iteratorB.next())) {
                return false;
            }
        }
        return !iteratorA.hasNext() && !iteratorB.hasNext();
    }

    protected static boolean doEquals(Object[] arrayA, Object[] arrayB) {
        if (arrayA.length != arrayB.length) {
            return false;
        }
        for (int i = 0; i < arrayA.length; i++) {
            if (!equals(arrayA[i], arrayB[i])) {
                return false;
            }
        }
        return true;
    }

    protected static Boolean doEqualsNonRecursive(Object a, Object b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return a == null && b == null;
        }
        if (a.getClass() != b.getClass()) {
            return false;
        }
        if (a instanceof boolean[] aArray && b instanceof boolean[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        if (a instanceof byte[] aArray && b instanceof byte[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        if (a instanceof double[] aArray && b instanceof double[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        if (a instanceof float[] aArray && b instanceof float[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        if (a instanceof int[] aArray && b instanceof int[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        if (a instanceof long[] aArray && b instanceof long[] bArray) {
            return Arrays.equals(aArray, bArray);
        }
        return null;
    }

    public static boolean equals(Object a, Object b) {
        final var nonRecursive = doEqualsNonRecursive(a, b);
        if (nonRecursive != null) {
            return nonRecursive;
        }
        if (a instanceof Object[]) {
            Object[] aArray = (Object[]) a;
            Object[] bArray = (Object[]) b;
            return doEquals(aArray, bArray);
        }
        if (a instanceof Iterable<?>) {
            final var iteratorA = ((Iterable<?>) a).iterator();
            final var iteratorB = ((Iterable<?>) b).iterator();
            return doEquals(iteratorA, iteratorB);
        }
        if (a instanceof Map<?, ?>) {
            final var iteratorA = ((Map<?, ?>) a).entrySet().iterator();
            final var iteratorB = ((Map<?, ?>) b).entrySet().iterator();
            return doEquals(iteratorA, iteratorB);
        }
        return a.equals(b);
    }

    public static int compare(final Comparable a, final Comparable b) {
        if (a == b) {
            return 0;
        }
        if (a == null) {
            return -1;
        }
        if (b == null) {
            return 1;
        }
        return a.compareTo(b);
    }

    public static int compare(final int a, final int b) {
        return Integer.compare(a, b);
    }

    public static int compare(final long a, final long b) {
        return Long.compare(a, b);
    }

    public static int compare(final float a, final float b) {
        return Float.compare(a, b);
    }

    public static int compare(final double a, final double b) {
        return Double.compare(a, b);
    }

    public static int compare(final boolean a, final boolean b) {
        return Boolean.compare(a, b);
    }

}
