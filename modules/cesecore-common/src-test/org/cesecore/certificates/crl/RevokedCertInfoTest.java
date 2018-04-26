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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Collection;

import org.cesecore.util.CompressedCollection;
import org.cesecore.util.ValidityDate;
import org.junit.Test;

/**
 * @version $Id$
 */
public class RevokedCertInfoTest {

    private static final RevokedCertInfo REVINFO_1_ONHOLD = revCertInfo(0x1234ABCDL, "2017-01-15", RevocationReasons.CERTIFICATEHOLD);
    private static final RevokedCertInfo REVINFO_2_NOTREVOKED = revCertInfo(0x1234ABCDL, "2017-01-31", RevocationReasons.NOT_REVOKED);
    private static final RevokedCertInfo REVINFO_3_UNSPECIFIED = revCertInfo(0x1234ABCDL, "2017-02-20", RevocationReasons.UNSPECIFIED);
    private static final RevokedCertInfo REVINFO_4_UNSPECIFIED = revCertInfo(0x1234ABCDL, "2017-03-31", RevocationReasons.UNSPECIFIED);
    private static final RevokedCertInfo REVINFO_5_REMOVEFROMCRL = revCertInfo(0x1234ABCDL, "2017-05-31", RevocationReasons.REMOVEFROMCRL);
    
    private static final RevokedCertInfo revCertInfo(final long serial, final String revocationDate, final RevocationReasons reason) {
        return new RevokedCertInfo(new byte[] { 1,2,3,4 }, BigInteger.valueOf(0x1234ABCDL).toByteArray(), date(revocationDate), reason.getDatabaseValue(), date("2017-12-31"));
    }
    
    private static final long date(final String ymd) {
        try {
            return ValidityDate.parseAsIso8601(ymd).getTime();
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
    private static void assertRCIEquals(final String message, final RevokedCertInfo expected, final RevokedCertInfo actual) {
        assertEquals(message, expected.getRevocationDate(), actual.getRevocationDate());
        assertEquals(message, expected.getReason(), actual.getReason());
    }
    
    @Test
    public void mergeEmpty() {
        final CompressedCollection<RevokedCertInfo> a = new CompressedCollection<>();
        a.add(REVINFO_2_NOTREVOKED);
        final CompressedCollection<RevokedCertInfo> b = new CompressedCollection<>();
        assertSame("Empty 'b' collection should cause 'a' to be returned.", a, RevokedCertInfo.mergeByDateAndStatus(a, b));
    }
    
    @Test
    public void mergeWithDuplicates() {
        final CompressedCollection<RevokedCertInfo> a = new CompressedCollection<>();
        final CompressedCollection<RevokedCertInfo> b = new CompressedCollection<>();
        b.add(REVINFO_2_NOTREVOKED);
        b.add(REVINFO_4_UNSPECIFIED); // permanent revocation => wins
        b.add(REVINFO_5_REMOVEFROMCRL);
        final Collection<RevokedCertInfo> res = RevokedCertInfo.mergeByDateAndStatus(a, b);
        assertEquals("Items should have been de-duplicated.", 1, res.size());
        assertRCIEquals("Should contain entry B.", REVINFO_4_UNSPECIFIED, res.iterator().next());
    }
    
    @Test
    public void mergeWithDuplicates2() {
        final CompressedCollection<RevokedCertInfo> a = new CompressedCollection<>();
        a.add(REVINFO_4_UNSPECIFIED); // permanent revocation => wins
        final CompressedCollection<RevokedCertInfo> b = new CompressedCollection<>();
        b.add(REVINFO_2_NOTREVOKED);
        b.add(REVINFO_5_REMOVEFROMCRL);
        final Collection<RevokedCertInfo> res = RevokedCertInfo.mergeByDateAndStatus(a, b);
        assertEquals("Items should have been de-duplicated.", 1, res.size());
        assertRCIEquals("Should contain entry B.", REVINFO_4_UNSPECIFIED, res.iterator().next());
    }
    
    @Test
    public void mergeWithDuplicates3() {
        final CompressedCollection<RevokedCertInfo> a = new CompressedCollection<>();
        final CompressedCollection<RevokedCertInfo> b = new CompressedCollection<>();
        b.add(REVINFO_2_NOTREVOKED); // only temporary revocations, and most recent entry => wins
        b.add(REVINFO_1_ONHOLD);
        final Collection<RevokedCertInfo> res = RevokedCertInfo.mergeByDateAndStatus(a, b);
        assertEquals("Items should have been de-duplicated.", 1, res.size());
        assertRCIEquals("Should contain entry B.", REVINFO_2_NOTREVOKED, res.iterator().next());
    }
    
    @Test
    public void mergeWithDuplicates4() {
        final CompressedCollection<RevokedCertInfo> a = new CompressedCollection<>();
        final CompressedCollection<RevokedCertInfo> b = new CompressedCollection<>();
        b.add(REVINFO_4_UNSPECIFIED);
        b.add(REVINFO_3_UNSPECIFIED); // permanent revocation with oldest date wins
        final Collection<RevokedCertInfo> res = RevokedCertInfo.mergeByDateAndStatus(a, b);
        assertEquals("Items should have been de-duplicated.", 1, res.size());
        assertRCIEquals("Should contain entry B.", REVINFO_3_UNSPECIFIED, res.iterator().next());
    }
    
}
