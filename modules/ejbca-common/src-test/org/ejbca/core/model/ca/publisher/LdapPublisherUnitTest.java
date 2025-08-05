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
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.junit.Test;

/**
 * Unit tests for {@link LdapPublisher}
 */
public class LdapPublisherUnitTest {

    @Test
    public void constructLdapDnSingle() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Collections.singleton(DNFieldExtractor.UID));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc", null));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc,C=SE", null));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc,C=SE", "UID=def"));
        assertEquals("Wrong DN with fields={UID} ", "UID=def,O=org", publ.constructLDAPDN("C=SE", "UID=def"));
    }

    @Test
    public void constructLdapDnMultiple() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,CN=name,OU=devs,O=org", publ.constructLDAPDN("CN=name,UID=abc,givenName=john,OU=devs", "C=SE"));
    }

    @Test
    public void constructLdapDnMultipleSameType() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,CN=name1,CN=name2,OU=devs,OU=ejbca,O=org", publ.constructLDAPDN("CN=name1,CN=name2,UID=abc,givenName=john,OU=devs,OU=ejbca", "O=org"));
    }

    @Test
    public void constructLdapDnMultipleCustomOrder() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseCustomDnOrder(true);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "CN=name,UID=abc,OU=devs,O=org", publ.constructLDAPDN("CN=name,UID=abc,givenName=john,OU=devs", "C=SE"));
    }

    @Test
    public void constructLdapDnMultipleSameTypeCustomOrder() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseCustomDnOrder(true);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "CN=name1,CN=name2,UID=abc,OU=devs,OU=ejbca,O=org", publ.constructLDAPDN("CN=name1,CN=name2,OU=devs,OU=ejbca,UID=abc,givenName=john", "O=org"));
    }
    
    @Test
    public void constructLdapDn_EmptyBaseDN() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.OU, DNFieldExtractor.O, DNFieldExtractor.L, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,OU=devs,OU=ejbca,O=org,L=Local,ST=Region,C=SE", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }

    @Test
    public void constructLdapDn_BlankBaseDN() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN(" "); // A space can be used via the webform.
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.OU, DNFieldExtractor.O, DNFieldExtractor.L, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,OU=devs,OU=ejbca,O=org,L=Local,ST=Region,C=SE", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }

    @Test
    public void constructLdapDn_WithBaseDN() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("dc=Root");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,O=org,ST=Region,C=SE,dc=Root", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }

}
