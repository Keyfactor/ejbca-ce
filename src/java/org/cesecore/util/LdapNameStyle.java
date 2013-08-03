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

package org.cesecore.util;

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * Name style used for parsing and building DNs for use with LDAP. 
 * 
 * @version $Id$
 */
public class LdapNameStyle extends BCStyle {

    public static final X500NameStyle INSTANCE = new LdapNameStyle();

    /**
     * default look up table translating OID values into their common symbols
     */
    public static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();

    /**
     * look up table translating common symbols into their OIDS.
     */
    private static final Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp = new Hashtable<String, ASN1ObjectIdentifier>();

    /**
     * look up table translating common symbols into their OIDS.
     */
    public static final Hashtable<String, String> DefaultStringStringLookUp = new Hashtable<String, String>();

    static {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "serialNumber");
        DefaultSymbols.put(EmailAddress, "mail");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");

        DefaultLookUp.put("c", C);
        DefaultLookUp.put("o", O);
        DefaultLookUp.put("t", T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", E);
        DefaultLookUp.put("mail", E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);

        DefaultStringStringLookUp.put("C", C.getId());
        DefaultStringStringLookUp.put("O", O.getId());
        DefaultStringStringLookUp.put("T", T.getId());
        DefaultStringStringLookUp.put("OU", OU.getId());
        DefaultStringStringLookUp.put("CN", CN.getId());
        DefaultStringStringLookUp.put("L", L.getId());
        DefaultStringStringLookUp.put("ST", ST.getId());
        DefaultStringStringLookUp.put("SN", SN.getId());
        DefaultStringStringLookUp.put("SERIALNUMBER", SN.getId());
        DefaultStringStringLookUp.put("STREET", STREET.getId());
        DefaultStringStringLookUp.put("EMAILADDRESS", E.getId());
        DefaultStringStringLookUp.put("MAIL", E.getId());
        DefaultStringStringLookUp.put("DC", DC.getId());
        DefaultStringStringLookUp.put("E", E.getId());
        DefaultStringStringLookUp.put("UID", UID.getId());
        DefaultStringStringLookUp.put("SURNAME", SURNAME.getId());
        DefaultStringStringLookUp.put("GIVENNAME", GIVENNAME.getId());
        DefaultStringStringLookUp.put("INITIALS", INITIALS.getId());
        DefaultStringStringLookUp.put("GENERATION", GENERATION.getId());
        DefaultStringStringLookUp.put("UNSTRUCTUREDADDRESS", UnstructuredAddress.getId());
        DefaultStringStringLookUp.put("UNSTRUCTUREDNAME", UnstructuredName.getId());
        DefaultStringStringLookUp.put("UNIQUEIDENTIFIER", UNIQUE_IDENTIFIER.getId());
        DefaultStringStringLookUp.put("DN", DN_QUALIFIER.getId());
        DefaultStringStringLookUp.put("PSEUDONYM", PSEUDONYM.getId());
        DefaultStringStringLookUp.put("POSTALADDRESS", POSTAL_ADDRESS.getId());
        DefaultStringStringLookUp.put("NAMEOFBIRTH", NAME_AT_BIRTH.getId());
        DefaultStringStringLookUp.put("COUNTRYOFCITIZENSHIP", COUNTRY_OF_CITIZENSHIP.getId());
        DefaultStringStringLookUp.put("COUNTRYOFRESIDENCE", COUNTRY_OF_RESIDENCE.getId());
        DefaultStringStringLookUp.put("GENDER", GENDER.getId());
        DefaultStringStringLookUp.put("PLACEOFBIRTH", PLACE_OF_BIRTH.getId());
        DefaultStringStringLookUp.put("DATEOFBIRTH", DATE_OF_BIRTH.getId());
        DefaultStringStringLookUp.put("POSTALCODE", POSTAL_CODE.getId());
        DefaultStringStringLookUp.put("BUSINESSCATEGORY", BUSINESS_CATEGORY.getId());
        DefaultStringStringLookUp.put("TELEPHONENUMBER", TELEPHONE_NUMBER.getId());
        DefaultStringStringLookUp.put("NAME", NAME.getId());
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
