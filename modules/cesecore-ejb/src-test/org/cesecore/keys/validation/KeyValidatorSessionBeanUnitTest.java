/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Test the key validator session bean.
 *
 */
public class KeyValidatorSessionBeanUnitTest {

    @Test
    public void testDNSInDomains() {
        var subject = "CN=Test, DNSNAME=domain1.com";
        var domains = KeyValidatorSessionBean.findAllDNSInSubject(subject);
        assertTrue(domains.contains("domain1.com"));
        assertEquals(1, domains.size());
    }

    @Test
    public void testMultipleDNSInDomains() {
        var subject = "CN=Test, DNSNAME=domain1.com, DNSNAME=domain2.com, DNSNAME=domain3.com";
        var domains = KeyValidatorSessionBean.findAllDNSInSubject(subject);
        assertTrue(domains.contains("domain1.com"));
        assertTrue(domains.contains("domain2.com"));
        assertTrue(domains.contains("domain3.com"));
        assertEquals(3, domains.size());
    }

    @Test
    public void testMultipleDNSInDomainsCaseInsensitive() {
        var subject = "CN=Test, dNSname=domain1.com, DNSNAME=domain2.com, dnsName=domain3.com";
        var domains = KeyValidatorSessionBean.findAllDNSInSubject(subject);
        assertTrue(domains.contains("domain1.com"));
        assertTrue(domains.contains("domain2.com"));
        assertTrue(domains.contains("domain3.com"));
        assertEquals(3, domains.size());
    }

    @Test
    public void testRFC822NameInDomains() {
        var subject = "CN=Test, rfc822name=test@domain.com";
        var domains = KeyValidatorSessionBean.findAllEmailDomainsInSubject(subject);
        assertTrue(domains.contains("domain.com"));
        assertEquals(1, domains.size());
    }

    @Test
    public void testMultipleEmailsInDomains() {
        var subject = "CN=Test, rfc822name=test@domain1.com, rfc822name=test@domain2.com, rfc822name=test@domain3.com";
        var domains = KeyValidatorSessionBean.findAllEmailDomainsInSubject(subject);
        assertTrue(domains.contains("domain1.com"));
        assertTrue(domains.contains("domain2.com"));
        assertTrue(domains.contains("domain3.com"));
        assertEquals(3, domains.size());
    }

    @Test
    public void testMultipleEmailsInDomainsCaseInsensitive() {
        var subject = "CN=Test, rfc822name=test@domain1.com, Rfc822Name=test@domain2.com, RFC822NAME=test@domain3.com";
        var domains = KeyValidatorSessionBean.findAllEmailDomainsInSubject(subject);
        assertTrue(domains.contains("domain1.com"));
        assertTrue(domains.contains("domain2.com"));
        assertTrue(domains.contains("domain3.com"));
        assertEquals(3, domains.size());
    }


}
