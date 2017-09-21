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
 * To inspect a test case manually, use dig e.g. <code>dig caa deny.basic.caatestsuite.com</code>.
 * </p>
 * <p>
 * A working Internet connection is required to make these tests pass, since an external DNS responder is used.
 * </p>
 * @version $Id: DnsCaaTestSuite.java 26598 2017-09-20 15:32:03Z bastianf $
 *
 */
public class CaaTestSuite {
    private CaaDnsLookupResult lookup(final String domain, final String issuer, final boolean dnssecEnabled)
            throws UnknownHostException, MalformedURLException {
        final Resolver dnsResolver = CaaDnsLookup.getDnsResolver("8.8.8.8", dnssecEnabled, null);
        final Map<String, CaaDnsLookupResult> lookupResults = CaaDnsLookup.performLookupForDomains(dnsResolver, issuer, dnssecEnabled, 100,
                new TopLevelDomainIgnoreList(null), domain);
        assertEquals(1, lookupResults.size());
        return lookupResults.get(domain + ".");
    }

    private CaaDnsLookupResult authorizedLookup(final String domain) throws UnknownHostException, MalformedURLException {
        return lookup(domain, "caatestsuite.com", false);
    }

    private CaaDnsLookupResult authorizedLookup(final String domain, final boolean dnssecEnabled) throws UnknownHostException, MalformedURLException {
        return lookup(domain, "caatestsuite.com", dnssecEnabled);
    }

    private CaaDnsLookupResult unauthorizedLookup(final String domain) throws UnknownHostException, MalformedURLException {
        return lookup(domain, "test", false);
    }

    @Test
    public void testEmptyBasic() throws Exception {
        // There are no CAA records here, no point in attempting an authorised lookup
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("empty.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
    }

    @Test
    public void testIssuanceBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testBigBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("big.basic.caatestsuite.com");
        // Issuer is indeed "test" but tag is not set to "issue"!
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
    }

    @Test
    public void testCritical1() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("critical1.basic.caatestsuite.com");
        assertEquals(ResultType.CRITICAL_TAG_NOT_FOUND, unauthorizedLookupResult.getResult());
    }

    @Test
    public void testCritical2() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("critical2.basic.caatestsuite.com");
        assertEquals(ResultType.CRITICAL_TAG_NOT_FOUND, unauthorizedLookupResult.getResult());
    }

    @Test
    public void testTreeClimbing1() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("sub1.deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("sub1.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testTreeClimbing2() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("sub2.sub1.deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("sub2.sub1.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testWildcard1() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("*.deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("*.deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testWildcard2() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("*.deny-wild.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("*.deny-wild.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED_WILDCARD, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS_WILDCARD, authorizedLookupResult.getResult());
    }

    @Test
    public void testCnameBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("cname-deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testCname2CnameBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("cname-cname-deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("cname-cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testSubdomainWithCname() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("sub1.cname-deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("sub1.cname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testDenyPermitBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("deny.permit.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("deny.permit.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testIpv6Only() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("ipv6only.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("ipv6only.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    @Test
    public void testDnssecExpiredSignature() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("expired.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, authorizedLookupResult.getResult());
    }

    @Test
    public void testDnssecMissingSignature() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("missing.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, authorizedLookupResult.getResult());
    }

    @Test
    public void testDnssecBlackhole() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("blackhole.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, authorizedLookupResult.getResult());
    }

    @Test
    public void testDnssecServerFail() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("servfail.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, authorizedLookupResult.getResult());
    }

    @Test
    public void testDnssecRefused() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("refused.caatestsuite-dnssec.com", true);
        assertEquals(ResultType.DNSSEC_VALIDATION_FAILED, authorizedLookupResult.getResult());
    }

    @Test
    public void testCnameLoop() throws Exception {
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("cname-loop.basic.caatestsuite.com");
        assertEquals(ResultType.LOOKUP_FAILED, authorizedLookupResult.getResult());
    }

    /**
     * NOTE: This test would be modified by erratum 5097 to RFC 6844.
     */
    @Test
    public void testDnameIssuanceBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("dname-deny.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("dname-deny.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }

    /**
     * NOTE: This test would be modified by erratum 5065 to RFC 6844.
     */
    @Test
    public void testCnameSubdomainIssuanceBasic() throws Exception {
        final CaaDnsLookupResult unauthorizedLookupResult = unauthorizedLookup("cname-deny-sub.basic.caatestsuite.com");
        final CaaDnsLookupResult authorizedLookupResult = authorizedLookup("cname-deny-sub.basic.caatestsuite.com");
        assertEquals(ResultType.ISSUANCE_PROHIBITED, unauthorizedLookupResult.getResult());
        assertEquals(ResultType.PASS, authorizedLookupResult.getResult());
    }
}
