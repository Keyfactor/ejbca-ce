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

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;

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

    private void logMemUnreliably() {
        System.gc();
        log.info("freeMemory: " + Runtime.getRuntime().freeMemory());
    }
}
