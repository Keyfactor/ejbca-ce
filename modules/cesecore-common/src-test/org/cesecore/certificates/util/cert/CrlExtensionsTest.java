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
package org.cesecore.certificates.util.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.junit.Test;

/**
 * Test of CrlExtensions utility class.
 * 
 * @version $Id$
 */
public class CrlExtensionsTest {

    /** Test extraction of revocation reason code when an CRL Entry has extensions like "Invalidity Date", but no X509v3 CRL Reason Code. */
    @Test
    public void testCrlEntryExtensionsButNoReasonCode() {
        final X509CRLEntry crlEntry = new X509CRLEntry() {
            @Override
            public boolean hasExtensions() {
                return true;
            }
            @Override
            public byte[] getExtensionValue(String oid) {
                if (Extension.reasonCode.getId().equals(oid)) {
                    return null;
                } else {
                    throw new UnsupportedOperationException();
                }
            }
            @Override
            public Set<String> getCriticalExtensionOIDs() {
                throw new UnsupportedOperationException();
            }
            @Override
            public Set<String> getNonCriticalExtensionOIDs() {
                throw new UnsupportedOperationException();
            }
            @Override
            public boolean hasUnsupportedCriticalExtension() {
                throw new UnsupportedOperationException();
            }
            @Override
            public byte[] getEncoded() throws CRLException {
                throw new UnsupportedOperationException();
            }
            @Override
            public Date getRevocationDate() {
                throw new UnsupportedOperationException();
            }
            @Override
            public BigInteger getSerialNumber() {
                throw new UnsupportedOperationException();
            }
            @Override
            public String toString() {
                throw new UnsupportedOperationException();
            }
        };
        try {
            assertEquals(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CrlExtensions.extractReasonCode(crlEntry));
        } catch (UnsupportedOperationException e) {
            fail("Test is no longer valid and needs to be updated.");
        }
    }
}
