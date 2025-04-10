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

package org.cesecore.certificates.ca;

import org.junit.Test;

import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;

public class KeepExpiredCertsOnCrlFormatUnitTest {

    private void doTestFromValue(final KeepExpiredCertsOnCrlFormat expected) {
        // When
        final var actual = KeepExpiredCertsOnCrlFormat.fromValue(expected.getValue());

        // Then
        assertEquals(expected, actual);
    }

    @Test
    public void testFromValue_CA_DATE() {
        doTestFromValue(KeepExpiredCertsOnCrlFormat.CA_DATE);
    }

    @Test
    public void testFromValue_ARBITRARY_DATE() {
        doTestFromValue(KeepExpiredCertsOnCrlFormat.ARBITRARY_DATE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromValue_invalidValue() {
        int max = Stream.of(KeepExpiredCertsOnCrlFormat.values())
                .map(KeepExpiredCertsOnCrlFormat::getValue)
                .max(Integer::compareTo)
                .orElse(0);
        KeepExpiredCertsOnCrlFormat.fromValue(max+1);
    }

}
