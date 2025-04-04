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

    private void doTestFromOrdinal(final KeepExpiredCertsOnCrlFormat expected) {
        // When
        final var actual = KeepExpiredCertsOnCrlFormat.fromOrdinal(expected.ordinal());

        // Then
        assertEquals(expected, actual);
    }

    @Test
    public void testFromOrdinal_CA_DATE() {
        doTestFromOrdinal(KeepExpiredCertsOnCrlFormat.CA_DATE);
    }

    @Test
    public void testFromOrdinal_ARBITRARY_DATE() {
        doTestFromOrdinal(KeepExpiredCertsOnCrlFormat.ARBITRARY_DATE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromOrdinal_invalidValue() {
        int max = Stream.of(KeepExpiredCertsOnCrlFormat.values())
                .map(KeepExpiredCertsOnCrlFormat::ordinal)
                .max(Integer::compareTo)
                .orElse(0);
        KeepExpiredCertsOnCrlFormat.fromOrdinal(max+1);
    }

}
