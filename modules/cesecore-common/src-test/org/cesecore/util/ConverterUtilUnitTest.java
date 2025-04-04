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
import java.time.ZoneId;

public class ConverterUtilUnitTest {

    @Test
    public void testConvertLocalDateTimeToEpochUtcAndBack() {
        // Given
        final var localDateTime = LocalDateTime.of(2025, Month.APRIL, 1, 14, 15, 31);

        // When
        final var epochUtc = ConverterUtils.localDateTimeToEpochUtc(localDateTime);

        // Then
        Assert.assertTrue(epochUtc > 0L);

        // When
        final var actual = ConverterUtils.epochUtcToLocalDateTime(epochUtc);

        // Then
        Assert.assertEquals(localDateTime, actual);
    }

    @Test
    public void showTimezone() {
        System.out.println(ZoneId.systemDefault());
    }

}
