/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util.validation.caa;

import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Map;

import org.ejbca.util.validation.caa.CaaDnsLookupResult.ResultType;
import org.junit.Test;
import org.xbill.DNS.Resolver;

/**
 * <p>
 * This is a test suite which checks compliance with CAA checking as defined in version 1.4.8 of the CA/Browser
 * Forum Baseline Requirements. Effective September 8, 2017, a CA which issues a certificate in violation of a
 * domain's CAA policy is in violation of the Baseline Requirements.
 * </p>
 * <p>
 * CAA Test Suite website: https://caatestsuite.com
 * </p>
 * <p>
 * A working Internet connection is required to make these tests pass, since an external DNS responder is used.
 * </p>
 * @version $Id: DnsCaaTestSuite.java 26598 2017-09-20 15:32:03Z bastianf $
 *
 */
public class CaaTestSuite {
    private CaaDnsLookupResult lookup(final String domain, final boolean dnssecEnabled) throws UnknownHostException, MalformedURLException {
        final Resolver dnsResolver = CaaDnsLookup.getDnsResolver("8.8.8.8", dnssecEnabled, null);
        // This test suite has CAA records for caatestsuite.com, so any other issuer should work
        final String issuer = "primekeyca.com";
        final Map<String, CaaDnsLookupResult> lookupResults = CaaDnsLookup.performLookupForDomains(dnsResolver, issuer, dnssecEnabled, 100,
                new TopLevelDomainIgnoreList(null), domain);
        assertEquals(1, lookupResults.size());
        return lookupResults.get(domain + ".");
    }

    private CaaDnsLookupResult lookup(final String domain) throws UnknownHostException, MalformedURLException {
        return lookup(domain, false);
    }

    @Test
    public void testEmptyBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("empty.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testDenyBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testBigBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("big.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testCritical1() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("critical1.basic.caatestsuite.com");
        assertEquals(ResultType.CRITICAL_TAG_NOT_FOUND, lookupResult.getResult());
    }

    @Test
    public void testCritical2() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("critical2.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testTreeClimbing1() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("sub1.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testTreeClimbing2() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("sub2.sub1.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testWildcard1() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("*.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testWildcard2() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("*.deny-wild.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED_WILDCARD, lookupResult.getResult());
    }

    @Test
    public void testCnameDenyBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testCname2CnameDenyBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("cname-cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testSubdomainWithCname() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("sub1.cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testDenyPermitBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("deny.permit.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testIpv6Only() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("ipv6only.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    @Test
    public void testDnssecExpiredSignature() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("expired.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, lookupResult.getResult());
    }

    @Test
    public void testDnssecMissingSignature() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("missing.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, lookupResult.getResult());
    }

    @Test
    public void testBlackhole() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("blackhole.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, lookupResult.getResult());
    }

    @Test
    public void testDnssecServerFail() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("servfail.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, lookupResult.getResult());
    }

    @Test
    public void testDnssecRefused() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("refused.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, lookupResult.getResult());
    }

    @Test
    public void testDnsCaaCrossSiteScripting() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("xss.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    /**
     * NOTE: This test would be modified by erratum 5097 to RFC 6844.
     */
    @Test
    public void testDnameDenyBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("dname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }

    /**
     * NOTE: This test would be modified by erratum 5065 to RFC 6844.
     */
    @Test
    public void testCnameDenySubdomainBasic() throws Exception {
        final CaaDnsLookupResult lookupResult = lookup("cname-deny-sub.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, lookupResult.getResult());
    }
}
