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
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 * Unit test for Partitioned CRL functionality in the X509CA class.
 * 
 * @version $Id$
 */
public class X509CACrlUnitTest extends X509CAUnitTestBase {

    private static final Logger log = Logger.getLogger(X509CACrlUnitTest.class);

    /**
     * Tests the extension CRL Distribution Point on CRLs
     */
    @Test
    public void testCRLDistPointOnCRL() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);

        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder crl = ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());

        byte[] cdpDER = xcrl.getExtensionValue(Extension.issuingDistributionPoint.getId());
        assertNotNull("CRL has no distribution points", cdpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cdpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        IssuingDistributionPoint cdp = IssuingDistributionPoint.getInstance(aIn.readObject());
        DistributionPointName distpoint = cdp.getDistributionPoint();

        assertEquals("CRL distribution point is different", cdpURL, ((DERIA5String) ((GeneralNames) distpoint.getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        ca.updateCA(cryptoToken, cainfo, cceConfig);
        crl = ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertNull("CRL has distribution points", xcrl.getExtensionValue(Extension.cRLDistributionPoints.getId()));
    }

    /**
     * Tests the extension Freshest CRL DP.
     *
     * @throws Exception
     *             in case of error.
     */
    @Test
    public void testCRLFreshestCRL() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);
        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        final String freshestCdpURL = "http://www.ejbca.org/foo/delta.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        cainfo.setCADefinedFreshestCRL(freshestCdpURL);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder crl = ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());

        byte[] cFreshestDpDER = xcrl.getExtensionValue(Extension.freshestCRL.getId());
        assertNotNull("CRL has no Freshest Distribution Point", cFreshestDpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cFreshestDpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        CRLDistPoint cdp = CRLDistPoint.getInstance(aIn.readObject());
        DistributionPoint[] distpoints = cdp.getDistributionPoints();

        assertEquals("More CRL Freshest distributions points than expected", 1, distpoints.length);
        assertEquals("Freshest CRL distribution point is different", freshestCdpURL, ((DERIA5String) ((GeneralNames) distpoints[0].getDistributionPoint()
                .getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        cainfo.setCADefinedFreshestCRL(null);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        crl = ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertNull("CRL has freshest crl extension", xcrl.getExtensionValue(Extension.freshestCRL.getId()));
    }

    private X509CAInfo createTestCaWithPartitionedCrl() throws Exception {
        log.trace(">createTestCaWithPartitionedCrl");
        final CryptoToken partitionedCrlCaCryptoToken = getNewCryptoToken();
        X509CA partitionedCrlCa = createTestCA(partitionedCrlCaCryptoToken, "CN=PartitionedCrlCa");
        X509CAInfo caInfo = (X509CAInfo) partitionedCrlCa.getCAInfo();
        caInfo.setUsePartitionedCrl(true);
        log.trace("<createTestCaWithPartitionedCrl");
        return caInfo;
    }

    /**
     * Tests the extension CRL Distribution Point on a partitioned CRL
     */
    @Test
    public void testPartitionedCRLDistPointOnCRL() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);

        final String cdpTemplateUrl = "http://www.ejbca.org/Foo*/Bar*.crl";
        final String cdpExpectedUrl = "http://www.ejbca.org/Foo12345/Bar12345.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setUsePartitionedCrl(true);
        cainfo.setCrlPartitions(23456);
        cainfo.setDefaultCRLDistPoint(cdpTemplateUrl);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder crl = ca.generateCRL(cryptoToken, 12345, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());

        assertEquals("CRL distribution point is different", Collections.singletonList(cdpExpectedUrl), CertTools.getCrlDistributionPoints(xcrl));

        crl = ca.generateDeltaCRL(cryptoToken, 12345, revcerts, 2, 1);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertEquals("CRL distribution point is different", Collections.singletonList(cdpExpectedUrl), CertTools.getCrlDistributionPoints(xcrl));
    }

    /**
     * Test that CRL CDP URLs generated for this CA are correct when using partitioned CRLs  
     */
    @Test
    public void shouldGenerateIndexedCrlPartitionUrls() throws Exception {
        log.trace(">shouldGenerateIndexedCrlPartitionUrls");
        // Given:
        final CryptoToken partitionedCrlCryptoToken = getNewCryptoToken();
        X509CA partitionedCrlCa = createTestCA(partitionedCrlCryptoToken, "CN=PartitionedCrlCa");
        X509CAInfo caInfo = (X509CAInfo) partitionedCrlCa.getCAInfo();
        //Setting use partitioned crl
        caInfo.setUsePartitionedCrl(true);
        caInfo.setCrlPartitions(15);
        //We make sure to have 11 non-suspended crl partitions left in use by retiring 4 partitions 
        caInfo.setSuspendedCrlPartitions(4);
        // When:
        //We use a template URL with the asterisk operator to generate our indexed URLs
        List<String> actualCdpUrl = caInfo.getAllCrlPartitionUrls("http://example.com/CA*.crl");
        int actualUrlListSize = actualCdpUrl.size();
        // Then:
        //The list should contain a minimum of one CRL CDP URL, as we always have a base URL
        assertNotNull("Returned list of CRL CDP URLs was null.", actualUrlListSize);
        //We should have 12 entries in the list of URLs
        assertEquals("Number of CRL partition URLs is incorrect.", 12, actualUrlListSize);
        //This URL should be modified without added index number (representing the base url)
        assertEquals("CRL CDP URL is incorrect.", "http://example.com/CA.crl", actualCdpUrl.get(0));
        //This URL should be modified with the index number '5' (representing the lowest used partition number)
        assertEquals("CRL partition index in URL is incorrect.", "http://example.com/CA5.crl", actualCdpUrl.get(1));
        //This URL should be modified with the index number '15' (representing the highest used partition number)
        assertEquals("CRL partition index in URL is incorrect.", "http://example.com/CA15.crl", actualCdpUrl.get(11));
        log.trace("<shouldGenerateIndexedCrlPartitionUrls");
    }

    /**
     * Test that one non-indexed CRL CDP URL is generated if not using partitioned CRLs configuration  
     */
    @Test
    public void shouldNotGenerateIndexedCrlPartitionUrlsIfFalse() throws Exception {
        log.trace(">shouldNotGenerateIndexedCrlPartitionUrlsIfFalse");
        // Given:
        final CryptoToken nonPartitionedCrlCaCryptoToken = getNewCryptoToken();
        X509CA nonPartitionedCrlCa = createTestCA(nonPartitionedCrlCaCryptoToken, "CN=NonPartitionedCrlCa");
        X509CAInfo caInfo = (X509CAInfo) nonPartitionedCrlCa.getCAInfo();
        //Setting use partitioned crl to false
        caInfo.setUsePartitionedCrl(false);
        //We add some partitions
        caInfo.setCrlPartitions(10);
        caInfo.setSuspendedCrlPartitions(5);
        // When:
        //We use a template URL with the asterisk operator to generate our indexed URLs
        List<String> actualCdpUrl = caInfo.getAllCrlPartitionUrls("http://example.com/CA*.crl");
        int actualUrlListSize = actualCdpUrl.size();
        // Then:
        //The list should not be null, as we have a base url
        assertNotNull("Returned list of CRL CDP URLs was null.", actualUrlListSize);
        //We should have 1 entry in the list of URLs, this is the base URL
        assertEquals("Number of CRL partition URLs should be 1.", 1, actualUrlListSize);
        //This URL should not have an index number, it is the base URL
        assertEquals("The URL should not contain a partition index.", "http://example.com/CA.crl", actualCdpUrl.get(0));
        log.trace("<shouldNotGenerateIndexedCrlPartitionUrlsIfFalse");
    }

    /**
     * Test that only one non-indexed CRL CDP URL is generated if all partitions are suspended
     * (this is an incorrect configuration, not allowed by the GUI)  
     */
    @Test
    public void shouldNotGenerateIndexedCrlPartitionUrlsIfAllSuspended() throws Exception {
        log.trace(">shouldNotGenerateIndexedCrlPartitionUrlsIfAllSuspended");
        // Given:
        final CryptoToken partitionedCrlCaCryptoToken = getNewCryptoToken();
        X509CA partitionedCrlCa = createTestCA(partitionedCrlCaCryptoToken, "CN=PartitionedCrlCa");
        X509CAInfo caInfo = (X509CAInfo) partitionedCrlCa.getCAInfo();
        //Setting use partitioned crl to true
        caInfo.setUsePartitionedCrl(true);
        //We add some partitions
        caInfo.setCrlPartitions(10);
        //We retire all partitions
        caInfo.setSuspendedCrlPartitions(10);
        // When:
        //We use a template URL with the asterisk operator to generate our indexed URLs
        List<String> actualCdpUrl = caInfo.getAllCrlPartitionUrls("http://example.com/CA*.crl");
        int actualUrlListSize = actualCdpUrl.size();
        // Then:
        //The list should not be null, as we have a base url
        assertNotNull("Returned list of CRL CDP URLs was null.", actualUrlListSize);
        //We should have 1 entry in the list of URLs, this is the base URL
        assertEquals("Number of CRL partition URLs should be 1.", 1, actualUrlListSize);
        //This URL should not have an index number, it is the base URL
        assertEquals("The URL should not contain a partition index.", "http://example.com/CA.crl", actualCdpUrl.get(0));
        log.trace("<shouldNotGenerateIndexedCrlPartitionUrlsIfAllSuspended");
    }

    /**
     * Test that a correct CRL CDP URL is generated when a partition index is provided  
     */
    @Test
    public void shouldGenerateCrlUrlBasedOnIndex() throws Exception {
        log.trace(">shouldGenerateCrlUrlBasedOnIndex");
        // Given:
        final CryptoToken partitionedCrlCaCryptoToken = getNewCryptoToken();
        X509CA partitionedCrlCa = createTestCA(partitionedCrlCaCryptoToken, "CN=PartitionedCrlCa");
        X509CAInfo caInfo = (X509CAInfo) partitionedCrlCa.getCAInfo();
        caInfo.setUsePartitionedCrl(true);
        // When:
        //We use a template URL with the asterisk operator to generate our indexed and non indexed URLs
        String actualCdpUrlforIndex0 = caInfo.getCrlPartitionUrl("http://example.com/CA*.crl", 0);
        String actualCdpUrlforIndex1 = caInfo.getCrlPartitionUrl("http://example.com/CA*.crl", 1);
        // Then:
        //We should have a URL without partition number for actualCdpUrlforIndex0
        assertEquals("CRL URL is wrong, should not contain partition index.", "http://example.com/CA.crl", actualCdpUrlforIndex0);
        //We should have a URL with a partition number '1' for actualCdpUrlforIndex1
        assertEquals("CRL URL is wrong, should contain correct partition index.", "http://example.com/CA1.crl", actualCdpUrlforIndex1);
        log.trace("<shouldGenerateCrlUrlBasedOnIndex");
    }

    /** Tests the determineCrlPartitionIndex method, with a URI without a partition wildcard character. */
    @Test
    public void determineCrlPartitionIndexWithoutPartition() throws Exception {
        log.trace(">determineCrlPartitionIndex");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://example.com/CA1.crl");
        assertEquals("With no asterisk in URI there should be no partitioning.", CertificateConstants.NO_CRL_PARTITION, caInfo.determineCrlPartitionIndex("http://example.com/CA1.crl"));
        log.trace("<determineCrlPartitionIndex");
    }

    /** Tests the determineCrlPartitionIndex method, with a URI with the default partition. */
    @Test
    public void determineCrlPartitionIndexWithDefaultPartitionUri() throws Exception {
        log.trace(">determineCrlPartitionIndexWithDefaultPartitionUri");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://example.com/CA*.crl");
        assertEquals("Test with default partition failed.", CertificateConstants.NO_CRL_PARTITION, caInfo.determineCrlPartitionIndex("http://example.com/CA.crl"));
        log.trace("<determineCrlPartitionIndexWithDefaultPartitionUri");
    }

    /** Tests the determineCrlPartitionIndex method, and with a URI with a partition index. */
    @Test
    public void determineCrlPartitionIndexWithPartitionInUri() throws Exception {
        log.trace(">determineCrlPartitionIndexWithPartitionInUri");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://example.com/CA*.crl");
        assertEquals("Test with one partition index failed.", 234, caInfo.determineCrlPartitionIndex("http://example.com/CA234.crl"));
        log.trace("<determineCrlPartitionIndexWithPartitionInUri");
    }

    /** Tests the determineCrlPartitionIndex method, with a URI with the partition index in two places. */
    @Test
    public void determineCrlPartitionIndexWithMultipleMatchingNumbers() throws Exception {
        log.trace(">determineCrlPartitionIndexWithMultipleMatchingNumbers");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://part*.crl.example.com/CA*.crl");
        assertEquals("Test with two partition indexes failed.", 3456, caInfo.determineCrlPartitionIndex("http://part3456.crl.example.com/CA3456.crl"));
        log.trace("<determineCrlPartitionIndexWithMultipleMatchingNumbers");
    }

    /** Tests the determineCrlPartitionIndex method, with a URI with the partition index in two places, with mismatch. */
    @Test
    public void determineCrlPartitionIndexWithMultipleMismatchingNumbers() throws Exception {
        log.trace(">determineCrlPartitionIndexWithMultipleMismatchingNumbers");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://part*.crl.example.com/CA*.crl");
        assertEquals("Test with mismatch should return 0 partition.", CertificateConstants.NO_CRL_PARTITION, caInfo.determineCrlPartitionIndex("http://part123.crl.example.com/CA456.crl"));
        log.trace("<determineCrlPartitionIndexWithMultipleMismatchingNumbers");
    }

    /** Tests the determineCrlPartitionIndex method, with special characters */
    @Test
    public void determineCrlPartitionIndexWithSpecialCharacters() throws Exception {
        log.trace(">determineCrlPartitionIndexWithSpecialCharacters");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint("http://part*.crl.example.com/strange\\xx\\\"test\\E++TEST*.crl");
        assertEquals("Test with partitioned CRL URI with special characters failed.", 987, caInfo.determineCrlPartitionIndex("http://part987.crl.example.com/strange\\xx\\\"test\\E++TEST987.crl"));
        log.trace("<determineCrlPartitionIndexWithSpecialCharacters");
    }

    /** Tests the determineCrlPartitionIndex method, with multiple logs but with no wildcard in CRL DP URI. */
    @Test
    public void determineCrlPartitionIndexMultipleCrlDpsNoPartitions() throws Exception {
        log.trace(">determineCrlPartitionIndexMultipleCrlDpsNoPartitions");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint(" http://example.com/CA1.crl ; http://example.com/CA2.crl ");
        assertEquals("With no asterisk in URL there should be no partitioning.", CertificateConstants.NO_CRL_PARTITION, caInfo.determineCrlPartitionIndex("http://example.com/CA1.crl"));
        log.trace("<determineCrlPartitionIndexMultipleCrlDpsNoPartitions");
    }

    /** Tests the determineCrlPartitionIndex method, with multiple logs and CRL partitions */
    @Test
    public void determineCrlPartitionIndexMultipleCrlDpsWithPartitions() throws Exception {
        log.trace(">determineCrlPartitionIndexMultipleCrlDpsWithPartitions");
        final X509CAInfo caInfo = createTestCaWithPartitionedCrl();
        caInfo.setDefaultCRLDistPoint(" http://example.com/CA*.crl ; http://crl*.example.net/CA*.crl ");
        assertEquals("Test with multiple CRL DPs with CRL partitioning failed.", 5, caInfo.determineCrlPartitionIndex("http://crl5.example.net/CA5.crl"));
        log.trace("<determineCrlPartitionIndexMultipleCrlDpsWithPartitions");
    }

    /** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
    @Test
    public void testAuthorityInformationAccessCrlExtension() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        X509CA testCa = createTestCA(cryptoToken, "CN=foo");
        List<String> authorityInformationAccess = new ArrayList<>();
        authorityInformationAccess.add("http://example.com/0");
        authorityInformationAccess.add("http://example.com/1");
        authorityInformationAccess.add("http://example.com/2");
        authorityInformationAccess.add("http://example.com/3");
        testCa.setAuthorityInformationAccess(authorityInformationAccess);
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 0);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
        Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
        assertEquals("Number of URLs do not match", authorityInformationAccess.size(), result.size());
        for(String url : authorityInformationAccess) {
            if(!result.contains(url)) {
                fail("URL " + url + " was not found.");
            }
        }
    }

    /** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
    @Test
    public void testAuthorityInformationAccessCrlExtensionWithEmptyList() throws Exception{
        final CryptoToken cryptoToken = getNewCryptoToken();
        X509CA testCa = createTestCA(cryptoToken, "CN=foo");
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 0);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
        Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
        assertEquals("A list was returned without any values present.", 0, result.size());
    }


}
