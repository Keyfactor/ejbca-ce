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

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.cesecore.util.CeSecoreNameStyle;

/**
 * Name style used for parsing and building DNs for use with LDAP. 
 * Used by LdapTools and LdapPublisher
 * 
 * @version $Id$
 */
public class LdapNameStyle extends BCStyle {

    public static final X500NameStyle INSTANCE = new LdapNameStyle();

    /**
     * Default look up table translating OID values into their common symbols
     * Please call initLookupTables() before using this!
     */
    public static Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols;

    /**
     * Look up table translating common symbols into their OIDS.
     * Please call initLookupTables() before using this!
     */
    private static Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp;

    /**
     * Look up table translating common symbols into their OIDS.
     * Please call initLookupTables() before using this!
     */
    public static Hashtable<String, String> DefaultStringStringLookUp;

    /**
     * Must call this method before using the lookup tables. It's automatically
     * called when using LdapNameStyle.INSTANCE to access this class.
     */
    public static void initLookupTables() {
        DefaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();
        DefaultLookUp = new Hashtable<String, ASN1ObjectIdentifier>();
        DefaultStringStringLookUp = new Hashtable<String, String>();
        
        // Copy from CeSecore
        DefaultSymbols.putAll(CeSecoreNameStyle.DefaultSymbols);
        DefaultLookUp.putAll(CeSecoreNameStyle.DefaultLookUp);
        DefaultStringStringLookUp.putAll(CeSecoreNameStyle.DefaultStringStringLookUp);
        
        // Apply differences in LDAP
        DefaultSymbols.put(SN, "serialNumber");
        DefaultSymbols.put(EmailAddress, "mail");
        DefaultLookUp.put("mail", E);
        DefaultStringStringLookUp.put("MAIL", E.getId());  // different from CeSecoreNameStyle
    }

    private LdapNameStyle() {
        if (DefaultSymbols == null) {
            initLookupTables();
        }
    }
    
    public String toString(X500Name name) {
        return CeSecoreNameStyle.buildString(DefaultSymbols, name);
    }
    
    @Override
    public ASN1ObjectIdentifier attrNameToOID(String attrName)
    {
        return IETFUtils.decodeAttrName(attrName, DefaultLookUp);
    }

}
