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

package org.cesecore.util;

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 *
 * @version $Id$
 *
 */
public class CeSecoreNameStyle extends BCStyle {

    public static final X500NameStyle INSTANCE = new CeSecoreNameStyle();

    /**
     * EV TLS jurisdictionCountry.
     * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
     */
    public static final ASN1ObjectIdentifier JURISDICTION_COUNTRY = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");
    /**
     * EV TLS jurisdictionState.
     * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
     */
    public static final ASN1ObjectIdentifier JURISDICTION_STATE = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2");
    /**
     * EV TLS jurisdictionLocality.
     * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
     */
    public static final ASN1ObjectIdentifier JURISDICTION_LOCALITY = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1");

    /**
     * default look up table translating OID values into their common symbols following
     * the convention in RFC 2253 with a few extras
     */
    public static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable<>();

    /**
     * look up table translating common symbols into their OIDS.
     */
    public static final Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp = new Hashtable<>();

    /**
     * look up table translating common symbols into their OIDS.
     */
    public static final Hashtable<String, String> DefaultStringStringLookUp = new Hashtable<>();

    static {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "SN");
        DefaultSymbols.put(EmailAddress, "E");
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
        DefaultSymbols.put(JURISDICTION_LOCALITY, "JurisdictionLocality");
        DefaultSymbols.put(JURISDICTION_STATE, "JurisdictionState");
        DefaultSymbols.put(JURISDICTION_COUNTRY, "JurisdictionCountry");

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
        DefaultLookUp.put("jurisdictionlocality", JURISDICTION_LOCALITY);
        DefaultLookUp.put("jurisdictionstate", JURISDICTION_STATE);
        DefaultLookUp.put("jurisdictioncountry", JURISDICTION_COUNTRY);

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
        DefaultStringStringLookUp.put("JURISDICTIONLOCALITY", JURISDICTION_LOCALITY.getId());
        DefaultStringStringLookUp.put("JURISDICTIONSTATE", JURISDICTION_STATE.getId());
        DefaultStringStringLookUp.put("JURISDICTIONCOUNTRY", JURISDICTION_COUNTRY.getId());
    }

    /**
     * This method is intended to be used in toString() in BCStyle classes. It is
     * useful e.g. when the DefaultSymbols map is not the default inherited from
     * BCStyle. It is public so it can be re-used by other classes as well
     * (e.g. LdapNameStyle in EJBCA).
     */
    public static String buildString(Hashtable<ASN1ObjectIdentifier,String> defaultSymbols, X500Name name) {
        StringBuffer buf = new StringBuffer();
        boolean first = true;

        RDN[] rdns = name.getRDNs();

        for (int i = 0; i < rdns.length; i++) {
            if (first) {
                first = false;
            } else {
                buf.append(',');
            }

            if (rdns[i].isMultiValued()) {
                AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
                boolean firstAtv = true;

                for (int j = 0; j != atv.length; j++) {
                    if (firstAtv) {
                        firstAtv = false;
                    } else {
                        buf.append('+');
                    }

                    IETFUtils.appendTypeAndValue(buf, atv[j], defaultSymbols);
                }
            } else {
                IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(), defaultSymbols);
            }
        }

        return buf.toString();
    }

    @Override
    public String toString(X500Name name) {
        return buildString(DefaultSymbols, name);
    }

    @Override
    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value) {
        // JurisdictionCountry is not included in BC (at least up to and including 1.49), and must be PrintableString
        if (oid.equals(CeSecoreNameStyle.JURISDICTION_COUNTRY)) {
            return new DERPrintableString(value);
        }
        return super.stringToValue(oid, value);
    }

}
