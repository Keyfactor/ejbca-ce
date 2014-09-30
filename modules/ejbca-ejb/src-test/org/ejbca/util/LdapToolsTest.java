/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 * @version $Id$
 */
public class LdapToolsTest {

    private static final String LDAP_TEST_DN = "cn=Test Person,mail=test@example.com,serialnumber=123456-7890";

    @Test
    public void test01GetParentDN() {
        assertEquals("", CertTools.getParentDN(""));
        assertEquals("", CertTools.getParentDN("dc=localhost"));
        assertEquals("dc=example,dc=com", CertTools.getParentDN("cn=test user,dc=example,dc=com").toLowerCase());
        assertEquals("dc=example,dc=com", CertTools.getParentDN("cn=test\\,user,dc=example,dc=com").toLowerCase());
        assertEquals("o=company\\,inc,dc=example,dc=com", CertTools.getParentDN("cn=user,o=company\\,inc,dc=example,dc=com").toLowerCase());
    }
    
    @Test
    public void test02GetFirstDNComponent() {
        assertEquals("", LdapTools.getFirstDNComponent(""));
        assertEquals("cn=user", LdapTools.getFirstDNComponent("cn=user").toLowerCase());
        assertEquals("cn=user", LdapTools.getFirstDNComponent("cn=user,dc=localhost").toLowerCase());
        assertEquals("cn=some\\,user", LdapTools.getFirstDNComponent("cn=some\\,user,dc=localhost").toLowerCase());
    }
    
    @Test
    public void test03GetIntermediateDNs() {
        assertEquals(0, LdapTools.getIntermediateDNs("dc=example,dc=com", "dc=example,dc=com").size());
        assertEquals(0, LdapTools.getIntermediateDNs("cn=user,dc=example,dc=com", "dc=example,dc=com").size());
        
        List<String> intDNs;
        
        intDNs = LdapTools.getIntermediateDNs("cn=user,o=company,dc=example,dc=com", "dc=example,dc=com");
        assertEquals(1, intDNs.size());
        assertEquals("o=company,dc=example,dc=com", intDNs.get(0).toLowerCase());
        
        intDNs = LdapTools.getIntermediateDNs("cn=user,mail=user@example.com,ou=safety department,o=company,dc=example,dc=com", "dc=example,dc=com");
        assertEquals(3, intDNs.size());
        assertEquals("o=company,dc=example,dc=com", intDNs.get(0).toLowerCase());
        assertEquals("ou=safety department,o=company,dc=example,dc=com", intDNs.get(1).toLowerCase());
        assertEquals("mail=user@example.com,ou=safety department,o=company,dc=example,dc=com", intDNs.get(2).toLowerCase());
    }
    
    /**
     * Tests parsing with LdapNameStyle class which is used by the LdapTools class.
     */
    @Test
    public void test04ParseLdapNameStyle() {
        // LDAP-specific attributes such as MAIL and SERIALNUMBER should work with LdapNameStyle...
        X500Name ldapName = new X500Name(LdapNameStyle.INSTANCE, LDAP_TEST_DN);
        assertEquals(LDAP_TEST_DN.toString().toLowerCase(), ldapName.toString().toLowerCase());
        
        // ...but they should not work with CeSecoreNameStyle
        try {
            new X500Name(CeSecoreNameStyle.INSTANCE, LDAP_TEST_DN);
            fail("LDAP-specific DN should not be accepted by CeSecoreNameStyle");
        } catch (Exception e) {
            // NOPMD: expected case
        }
    }
    
    /**
     * Tests name builder with LdapNameStyle class which is used by the LdapTools class.
     */
    @Test
    public void test05BuildLdapNameStyle() {
        X500Name ldapName = new X500Name(LdapNameStyle.INSTANCE, LDAP_TEST_DN);
        
        // LdapNameStyle should return a DN with MAIL and SERIALNUMBER
        X500NameBuilder ldapNameBuilder = new X500NameBuilder(LdapNameStyle.INSTANCE);
        for (RDN rdn : ldapName.getRDNs()) {
            for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                ldapNameBuilder.addRDN(atv);
            }
        }
        assertEquals(LDAP_TEST_DN.toLowerCase(), ldapNameBuilder.build().toString().toLowerCase());
        
        // CesecoreNameStyle should return a DN with E and SN
        X500NameBuilder cesecoreNameBuilder = new X500NameBuilder(CeSecoreNameStyle.INSTANCE);
        for (RDN rdn : ldapName.getRDNs()) {
            for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                cesecoreNameBuilder.addRDN(atv);
            }
        }
        assertEquals("cn=test person,e=test@example.com,sn=123456-7890", cesecoreNameBuilder.build().toString().toLowerCase());
    }

}
