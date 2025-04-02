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

import org.junit.Assert;
import org.junit.Test;

import java.time.LocalDateTime;
import java.time.Month;

public class ConverterUtilUnitTest {

    @Test
    public void testLocalDateTimeToString() {
        // Given
        final var localDateTime = LocalDateTime.of(2025, Month.APRIL, 1, 14, 15, 31);
        final var expected = "2025-04-01T14:15:31";

        // When
        final var actual = ConverterUtils.localDateTimeToString(localDateTime);

        // Then
        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testStringToLocalDateTime() {
        // Given
        final var localDateTimeAsString = "2025-04-01T14:15:31";
        final var expected = LocalDateTime.of(2025, Month.APRIL, 1, 14, 15, 31);

        // When
        final var actual = ConverterUtils.parseLocalDateTime(localDateTimeAsString);

        // Then
        Assert.assertEquals(expected, actual);
    }

}
