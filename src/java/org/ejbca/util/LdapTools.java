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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.cesecore.util.CertTools;

import com.novell.ldap.LDAPDN;

/**
 * Various utility methods for working with LDAP DN strings.
 * 
 * @version $Id$
 */
public final class LdapTools {

    // should not be instantiated
    private LdapTools() {}
    
    /**
     * Returns the first component in a DN string, e.g. if the input is
     * "cn=User,dc=example,dc=com" then it would return "cn=User".
     */
    public static String getFirstDNComponent(String dn) {
        List<String> components = CertTools.getX500NameComponents(dn);
        if (components.size() == 0 || StringUtils.isEmpty(components.get(0))) return "";
        else return LDAPDN.escapeRDN(components.get(0));
    }
    
    /**
     * Returns all intermediate DNs in a given DN under a base DN, in the order from the
     * first one below the base DN and further down.
     */
    public static List<String> getIntermediateDNs(String dn, String baseDN) {
        // Remove the base DN
        if (!dn.endsWith(baseDN)) return new ArrayList<String>();
        final String subDN = dn.substring(0, dn.length()-baseDN.length());
        
        // Split and escape the DN (but ignore the lowest level component)
        final List<String> components = new ArrayList<String>();
        for (String comp : CertTools.getX500NameComponents(CertTools.getParentDN(subDN))) {
            if (!StringUtils.isEmpty(comp)) {
                components.add(LDAPDN.escapeRDN(comp));
            }
        }
        
        // Add each intermediate DN
        final List<String> ret = new ArrayList<String>();
        for (int start = components.size()-1; start >= 0; start--) {
            final List<String> intermComps = components.subList(start, components.size());
            final X500NameBuilder nameBuilder = new X500NameBuilder(LdapNameStyle.INSTANCE);
            for (String comp : intermComps) {
                final RDN rdn = new X500Name(LdapNameStyle.INSTANCE, comp).getRDNs()[0];
                nameBuilder.addRDN(rdn.getFirst());
            }
            ret.add(nameBuilder.build().toString() + "," + baseDN);
        }
        return ret;
    }

}
