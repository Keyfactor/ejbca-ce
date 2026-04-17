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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import java.util.Date;

import org.junit.Test;

/**
 * Unit tests for {@link LimitedCertificateEntry}.
 */
public class LimitedCertificateEntryUnitTest {

    private static final BigInteger SERIAL_NUMBER = new BigInteger("123456789");
    private static final Date REVOCATION_DATE = new Date(1700000000000L);
    private static final Date INVALIDITY_DATE = new Date(1699999000000L);
    private static final int REASON_CODE = 4; // superseded

    @Test
    public void shouldStoreAllFieldsCorrectly() {
        final LimitedCertificateEntry entry = new LimitedCertificateEntry(SERIAL_NUMBER, REVOCATION_DATE, INVALIDITY_DATE, REASON_CODE);
        assertEquals(SERIAL_NUMBER, entry.getSerialNumber());
        assertEquals(REVOCATION_DATE, entry.getRevocationDate());
        assertEquals(INVALIDITY_DATE, entry.getInvalidityDate());
        assertEquals(REASON_CODE, entry.getReasonCode());
    }

    @Test
    public void shouldHandleNullInvalidityDate() {
        final LimitedCertificateEntry entry = new LimitedCertificateEntry(SERIAL_NUMBER, REVOCATION_DATE, null, REASON_CODE);
        assertNotNull(entry.getRevocationDate());
        assertNull(entry.getInvalidityDate());
    }

    /** Verifies that getRevocationDate returns a defensive copy so callers cannot mutate internal state. */
    @Test
    public void shouldReturnDefensiveCopyOfRevocationDate() {
        final LimitedCertificateEntry entry = new LimitedCertificateEntry(SERIAL_NUMBER, REVOCATION_DATE, INVALIDITY_DATE, REASON_CODE);
        final Date expectedRevocationDate = new Date(REVOCATION_DATE.getTime());
        final Date returnedDate = entry.getRevocationDate();
        assertNotSame("getRevocationDate should return a new Date instance", returnedDate, entry.getRevocationDate());
        // Mutate the returned date and verify internal state is unchanged
        returnedDate.setTime(0L);
        assertEquals("Internal revocation date must not be affected by mutation of returned copy",
                expectedRevocationDate, entry.getRevocationDate());
    }

    /** Verifies that getInvalidityDate returns a defensive copy so callers cannot mutate internal state. */
    @Test
    public void shouldReturnDefensiveCopyOfInvalidityDate() {
        final LimitedCertificateEntry entry = new LimitedCertificateEntry(SERIAL_NUMBER, REVOCATION_DATE, INVALIDITY_DATE, REASON_CODE);
        final Date expectedInvalidityDate = new Date(INVALIDITY_DATE.getTime());
        final Date returnedDate = entry.getInvalidityDate();
        assertNotSame("getInvalidityDate should return a new Date instance", returnedDate, entry.getInvalidityDate());
        // Mutate the returned date and verify internal state is unchanged
        returnedDate.setTime(0L);
        assertEquals("Internal invalidity date must not be affected by mutation of returned copy",
                expectedInvalidityDate, entry.getInvalidityDate());
    }
}
