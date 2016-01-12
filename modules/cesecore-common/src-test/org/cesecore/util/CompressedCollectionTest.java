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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.junit.Test;

/**
 * Sanity checks of the CompressedCollection that provides memory efficient Iterable object storage.
 * 
 * @version $Id$
 */
public class CompressedCollectionTest {
    
    private static final Logger log = Logger.getLogger(CompressedCollectionTest.class);

    @Test
    public void testCompression() throws IOException {
        log.trace(">testCompression");
        logMemUnreliably();
        log.trace("Adding plenty of (identical) RevokedCertInfos...");
        Collection<RevokedCertInfo> compressedCollection = new CompressedCollection<RevokedCertInfo>();
        for (int i=0; i<100000; i++) {
            compressedCollection.add(new RevokedCertInfo("fingerprint".getBytes(), new BigInteger("1").toByteArray(), System.currentTimeMillis(), CertificateConstants.CERT_REVOKED, System.currentTimeMillis()));
        }
        logMemUnreliably();
        log.trace("Iterating once..");
        // Test that .iterator is used in for each and not .toArray
        for (final RevokedCertInfo x : compressedCollection) {
            //log.info("  " + x.toString());
        }
        logMemUnreliably();
        log.trace("Iterating twice..");
        for (final RevokedCertInfo x : compressedCollection) {
            //log.info("  " + x.toString());
        }
        logMemUnreliably();
        log.trace("Cleaning up...");
        compressedCollection.clear();
        compressedCollection.clear();    // Make sure that we can call clear multiple times
        compressedCollection = null;
        logMemUnreliably();
        log.trace("<testCompression");
    }

    @Test
    public void testEmpty() throws IOException {
        log.trace(">testEmpty");
        Collection<RevokedCertInfo> compressedCollection = new CompressedCollection<RevokedCertInfo>();
        for (final RevokedCertInfo x : compressedCollection) {
            log.info("  " + x.toString());
        }
        compressedCollection.clear();
        log.trace("<testEmpty");
    }
    
    @Test
    public void testNoAddAfterClose() {
        final CompressedCollection<Integer> compressedCollection = new CompressedCollection<Integer>();
        compressedCollection.add(Integer.valueOf(4711));
        assertEquals("Compressed collection with single entry should have size 1.", 1, compressedCollection.size());
        // For loop with invoke compressedCollection.iterator() that will invoke closeForWrite() making it impossible for future changes
        for (final Integer i : compressedCollection) {
            assertEquals(4711, i.intValue());
        }
        // Try to add new element
        try {
            compressedCollection.add(Integer.valueOf(5));
            fail("CompressedCollection should not allow add after closeForWrite().");
        } catch (IllegalStateException e) {
            log.debug(e.getMessage());
        }
        assertEquals("Nothing more should have been added after closeForWrite().", 1, compressedCollection.size());
        compressedCollection.clear();
        assertEquals("Cleared compressed collection should have size 0.", 0, compressedCollection.size());
        compressedCollection.add(Integer.valueOf(4711));
        assertEquals("Compressed collection with single entry should have size 1.", 1, compressedCollection.size());
        final Iterator<Integer> iter = compressedCollection.iterator();
        assertTrue(iter.hasNext());
        assertEquals(4711, iter.next().intValue());
        assertFalse(iter.hasNext());
        compressedCollection.clear();
    }

    private void logMemUnreliably() {
        System.gc();
        // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
        final long maxAllocation = Runtime.getRuntime().maxMemory();
        // The total amount of memory allocated to the JVM.
        final long currentlyAllocation = Runtime.getRuntime().totalMemory();
        // Available memory of what is allocated by the JVM
        final long freeAllocated = Runtime.getRuntime().freeMemory();
        // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
        final long currentFreeMemory = maxAllocation - currentlyAllocation + freeAllocated;
        log.info("freeMemory: " + currentFreeMemory);
    }
}
