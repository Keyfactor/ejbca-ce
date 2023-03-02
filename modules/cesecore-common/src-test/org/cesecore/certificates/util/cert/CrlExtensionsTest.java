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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * Test of CrlExtensions utility class.
 * 
 * @version $Id$
 */
public class CrlExtensionsTest {
    
    private static byte[] testcrl = Base64.decode(("MIHGMHICAQEwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEVEVTVBcNMTEwMTMx"
            +"MTMzOTE3WhcNMTEwMTMxMTMzOTE3WqAvMC0wHwYDVR0jBBgwFoAUt39s38+I8fP0"
            +"diUs8Y8TYtCar8gwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADQQBcr4CF0sy3"
            +"5sVvEafzh67itIasqcv/PwUT6DwQxoiX85h53cFtvXQxi/2Xqn+PaNBOqWShByX7"
            +"TQlMX0Bmoz9/").getBytes());

    
    private static byte[] testdeltacrl = Base64.decode(("MIHWMIGBAgEBMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRFU1QXDTExMDEz"
            +"MTEzNDcxOFoXDTExMDEzMTEzNDcxOFqgPjA8MB8GA1UdIwQYMBaAFJ5BHYGqJr3K"
            +"j9IMQxmMP6ad8gDdMAoGA1UdFAQDAgEDMA0GA1UdGwEB/wQDAgECMA0GCSqGSIb3"
            +"DQEBCwUAA0EAP8CIPLll5m/wmhcLL5SXlb+aYrPGsUlBFNBKYKO0iV1QjBHeDMp5"
            +"z70nU3g2tIfiEX4IKNFyzFvn5m6e8m0JQQ==").getBytes());

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
    
    @Test
    public void testCRLs() throws Exception {
        X509CRL crl = CertTools.getCRLfromByteArray(testcrl);
        assertEquals("CN=TEST", CertTools.getIssuerDN(crl));
        byte[] pembytes = CertTools.getPEMFromCrl(testcrl);
        String pem = new String(pembytes);
        assertTrue(pem.contains("BEGIN X509 CRL"));
        assertEquals(1, CrlExtensions.getCrlNumber(crl).intValue());
        assertEquals(-1, CrlExtensions.getDeltaCRLIndicator(crl).intValue());

        X509CRL deltacrl = CertTools.getCRLfromByteArray(testdeltacrl);
        assertEquals(3, CrlExtensions.getCrlNumber(deltacrl).intValue());
        assertEquals(2, CrlExtensions.getDeltaCRLIndicator(deltacrl).intValue());

    }
}
