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
package org.ejbca.ui.web.rest.api.util;

import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Objects;

public class AssertUtil {

    protected static int getMaxLength(final Collection<?> collection) {
        return collection == null ?
                0 : collection
                        .stream()
                        .map(Object::toString)
                        .mapToInt(x -> x.length()).max().orElse(0);
    }

    public static <T> void assertEquals(final Collection<T> expected, final Collection<T> actual) {
        if (expected == null && actual == null) {
            return;
        }
        if (expected == null) {
            fail("Expected: null,  Actual: not null");
        }
        if (actual == null) {
            fail("Expected: not null,  Actual: null");
        }
        int maxExpectedLength = Math.max("Expected:".length(), getMaxLength(expected));
        int maxActualLength   = Math.max("Actual:".length(),   getMaxLength(actual));
        String format = "%-"+maxExpectedLength+"s   %-"+maxActualLength+"s  %s\n";
        StringBuilder message = new StringBuilder("\n");
        message.append(String.format(format, "Expected:", "Actual:", ""));
        final var expectedIterator = expected.iterator();
        final var actualIterator = actual.iterator();
        boolean different = false;
        while (expectedIterator.hasNext() && actualIterator.hasNext()) {
            final var expectedElement = expectedIterator.next();
            final var actualElement = actualIterator.next();
            if (Objects.equals(expectedElement, actualElement)) {
                message.append(String.format(format, expectedElement, actualElement, ""));
            }
            else {
                message.append(String.format(format, expectedElement, actualElement, "Different"));
                different = true;
            }
        }
        while (expectedIterator.hasNext()) {
            final var expectedElement = expectedIterator.next();
            message.append(String.format(format, expectedElement, "", "Different"));
            different = true;
        }
        while (actualIterator.hasNext()) {
            final var actualElement = actualIterator.next();
            message.append(String.format(format, "", actualElement, "Different"));
            different = true;
        }
        if (different) {
            fail(message.toString());
        }
    }

}
