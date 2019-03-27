/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.certextensions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.cesecore.certificates.ca.X509CAImpl;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.X509CAInfo.X509CAInfoBuilder;
import org.cesecore.certificates.certificate.certextensions.standard.CrlDistributionPoints;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 * @version $Id$
 */
public class CrlDistributionPointsUnitTest {

    private static final Logger log = Logger.getLogger(CrlDistributionPointsUnitTest.class);

    private static final String TEST_SUBJECTDN = "CN=User,O=Org";
    private static final String TEST_URL = "http://example.com/CA.crl";
    private static final String TEST2_URL = "http://crl.example.net/CA.crl";
    private static final String PARTITIONED_A_URL = "http://crl*.a.example.com/CA_*.crl";
    private static final String PARTITION_A_2_URL = "http://crl2.a.example.com/CA_2.crl";
    private static final String PARTITION_A_3_URL = "http://crl3.a.example.com/CA_3.crl";
    private static final String PARTITIONED_B_URL = "http://crl*.b.example.com/CA_*.crl";
    private static final String PARTITION_B_2_URL = "http://crl2.b.example.com/CA_2.crl";
    private static final String PARTITION_B_3_URL = "http://crl3.b.example.com/CA_3.crl";

    private final CrlDistributionPoints ext = new CrlDistributionPoints();
    private final EndEntityInformation endEntity = new EndEntityInformation();
    private final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    {
        certProfile.setUseCRLDistributionPoint(true);
        certProfile.setUseDefaultCRLDistributionPoint(true);
    }

    /** Tests with one CRL Distribution Point URL */
    @Test
    public void oneUri() throws Exception {
        log.trace(">basicTest");
        final X509CAInfo caInfo = new X509CAInfoBuilder()
                .setSubjectDn(TEST_SUBJECTDN)
                .setDefaultCrlDistPoint(TEST_URL)
                .build();
        final byte[] encoded = ext.getValueEncoded(endEntity, new X509CAImpl(caInfo), certProfile, null, null, null);
        assertNotNull("Should return a CRL DP extension", encoded);
        assertEquals(Collections.singletonList(TEST_URL), getCrlDistPoints(encoded));
        log.trace("<basicTest");
    }

    /** Tests with two CRL Distribution Point URL */
    @Test
    public void multiUri() throws Exception {
        log.trace(">basicTest");
        final X509CAInfo caInfo = new X509CAInfoBuilder()
                .setSubjectDn(TEST_SUBJECTDN)
                .setDefaultCrlDistPoint(TEST_URL + ";" + TEST2_URL)
                .build();
        final byte[] encoded = ext.getValueEncoded(endEntity, new X509CAImpl(caInfo), certProfile, null, null, null);
        assertNotNull("Should return a CRL DP extension", encoded);
        assertEquals(Arrays.asList(TEST_URL, TEST2_URL), getCrlDistPoints(encoded));
        log.trace("<basicTest");
    }

    /** Tests with two CRL Distribution Point URL with CRL Partitioning */
    @Test
    public void partitionedCrl() throws Exception {
        log.trace(">basicTest");
        final X509CAInfo caInfo = new X509CAInfoBuilder()
                .setSubjectDn(TEST_SUBJECTDN)
                .setDefaultCrlDistPoint(PARTITIONED_A_URL + ";" + PARTITIONED_B_URL)
                .setUsePartitionedCrl(true)
                .setRetiredCrlPartitions(1)
                .setCrlPartitions(3)
                .build();
        // Should get partition 2 or 3, but never partition 1, and never a mix of 2 and 3
        boolean gotPartition2 = false;
        boolean gotPartition3 = false;
        for (int i = 0; i < 50; i++) { // it is randomly allocated, so try multiple times
            final byte[] encoded = ext.getValueEncoded(endEntity, new X509CAImpl(caInfo), certProfile, null, null, null);
            assertNotNull("Should return a CRL DP extension", encoded);
            final Collection<String> distPoints = getCrlDistPoints(encoded);
            if (Arrays.asList(PARTITION_A_2_URL, PARTITION_B_2_URL).equals(distPoints)) {
                gotPartition2 = true;
            } else if (Arrays.asList(PARTITION_A_3_URL, PARTITION_B_3_URL).equals(distPoints)) {
                gotPartition3 = true;
            } else {
                fail("Got unexpected distribution points: " + distPoints);
            }
        }
        assertTrue("Never got partition 2 in 50 tries.", gotPartition2);
        assertTrue("Never got partition 3 in 50 tries.", gotPartition3);
        log.trace("<basicTest");
    }

    private Collection<String> getCrlDistPoints(final byte[] encodedExtension) throws IOException {
        return CertTools.getCrlDistributionPoints(ASN1Primitive.fromByteArray(encodedExtension));
    }
}
