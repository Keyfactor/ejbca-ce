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

package org.cesecore.certificates.util;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.ietf.ldap.LDAPDN;

/**
 * A class used to retrieve different fields from a Distinguished Name or Subject Alternate Name or Subject Directory Attributes strings.
 */
public class DNFieldExtractor implements Serializable {

    private static final long serialVersionUID = -1313839342568999844L;

    private static final Logger log = Logger.getLogger(DNFieldExtractor.class);
    // Public constants
    public static final int TYPE_SUBJECTDN = 0;
    public static final int TYPE_SUBJECTALTNAME = 1;
    public static final int TYPE_SUBJECTDIRATTR = 2;

    // Note, these IDs duplicate values in profilemappings.properties

    // Subject DN Fields.
    public static final int E = 0;
    public static final int UID = 1;
    public static final int CN = 2;
    public static final int SN = 3;
    public static final int GIVENNAME = 4;
    public static final int INITIALS = 5;
    public static final int SURNAME = 6;
    public static final int T = 7;
    public static final int OU = 8;
    public static final int O = 9;
    public static final int L = 10;
    public static final int ST = 11;
    public static final int DC = 12;
    public static final int C = 13;
    public static final int UNSTRUCTUREDADDRESS = 14;
    public static final int UNSTRUCTUREDNAME = 15;
    public static final int POSTALCODE = 32;
    public static final int BUSINESSCATEGORY = 33;
    public static final int DN = 34;
    public static final int POSTALADDRESS = 35;
    public static final int TELEPHONENUMBER = 36;
    public static final int PSEUDONYM = 37;
    public static final int STREET = 38;
    public static final int NAME = 55;
    public static final int ROLE = 70;
    public static final int DESCRIPTION = 60;
    public static final int ORGANIZATIONIDENTIFIER = 106;
    public static final int VID = 107;
    public static final int PID = 108;

    // Subject Alternative Names.
    public static final int OTHERNAME = 16;
    public static final int RFC822NAME = 17;
    public static final int DNSNAME = 18;
    public static final int IPADDRESS = 19;
    public static final int X400ADDRESS = 20;
    public static final int DIRECTORYNAME = 21;
    public static final int EDIPARTYNAME = 22;
    public static final int URI = 23;
    public static final int REGISTEREDID = 24;
    public static final int UPN = 25;
    public static final int GUID = 26;
    public static final int KRB5PRINCIPAL = 52;
    public static final int PERMANTIDENTIFIER = 56;
    public static final int SUBJECTIDENTIFICATIONMETHOD = 59;
    
    // Subject Directory Attributes
    public static final int DATEOFBIRTH = 27;
    public static final int PLACEOFBIRTH = 28;
    public static final int GENDER = 29;
    public static final int COUNTRYOFCITIZENSHIP = 30;
    public static final int COUNTRYOFRESIDENCE = 31;

    private static final int BOUNDRARY = 100;
    /** Mapping dnid to number of occurrences in this DN */
    private HashMap<Integer, Integer> fieldnumbers;
    /** mapping dn (or altname or subject dir attrs) numerical ids with the value of the components */
    private HashMap<Integer, String> dnfields;
    private boolean existsother = false;
    private boolean illegal = false;
    /** We want to know if the DN has some multi value RDNs */
    private boolean hasMultiValueRDN = false;
    private int type;

    public int getType() {
        return type;
    }
    
    /**
     * Creates a new instance of DNFieldExtractor
     * 
     * @param dn the DN we want to process for example CN=Tomas,O=PrimeKey,C=SE
     * @param type one of the constants {@link #TYPE_SUBJECTDN}, {@link #TYPE_SUBJECTALTNAME}, {@link #TYPE_SUBJECTDIRATTR}
     * @throws IllegalArgumentException if DN is multi-valued but has multi-values that are not one on {@link #allowedMulti} 
     */
    public DNFieldExtractor(final String dn, final int type) throws IllegalArgumentException {
        dnfields = new HashMap<>();
        setDN(dn, type);
    }

    /**
     * Fields that can be selected in Certificate profile and Publisher
     */
    public static List<Integer> getUseFields(final int type) {
        if (type == DNFieldExtractor.TYPE_SUBJECTDN) {
            return DnComponents.getDnDnIds();
        } else if (type == DNFieldExtractor.TYPE_SUBJECTALTNAME) {
            return DnComponents.getAltNameDnIds();
        } else if (type == DNFieldExtractor.TYPE_SUBJECTDIRATTR) {
            return DnComponents.getDirAttrDnIds();
        } else {
            return new ArrayList<>();
        }
    }
    
    /**
     * Returns the valid components for the given DN type (Subject DN, Subject Alternative Name or Subject Directory Attributes)
     * @param dnType DNFieldExtractor.TYPE_&ast;
     * @return List of valid components from DnComponents.&ast;
     */
    public static List<String> getValidFieldComponents(final int dnType) {
        switch (dnType) {
        case DNFieldExtractor.TYPE_SUBJECTDN: return DnComponents.getDnProfileFields();
        case DNFieldExtractor.TYPE_SUBJECTALTNAME: return DnComponents.getAltNameFields();
        case DNFieldExtractor.TYPE_SUBJECTDIRATTR: return DnComponents.getDirAttrFields();
        default: throw new IllegalArgumentException("Invalid DN type");
        }
    }

    public static String getFieldComponent(final int field, final int type) {
        final String ret;
        if (type == DNFieldExtractor.TYPE_SUBJECTDN) {
            ret = DnComponents.getDnExtractorFieldFromDnId(field);
        } else if (type == DNFieldExtractor.TYPE_SUBJECTALTNAME) {
            ret = DnComponents.getAltNameExtractorFieldFromDnId(field);
        } else {
            ret = DnComponents.getDirAttrExtractorFieldFromDnId(field);
        }
        return ret;
    }

    /**
     * Looks up a DN Id (for use with DnComponents functions etc.) from a DN component.
     * @param dnComponent Component, e.g. "CN". Not case sensitive.
     * @param dnType DN type, e.g. DNFieldExtractor.TYPE_SUBJECTDN
     * @return DN Id, or null if no such component exists for the given DN type.
     */
    public static Integer getDnIdFromComponent(final String dnComponent, final int dnType) {
        switch (dnType) {
        case DNFieldExtractor.TYPE_SUBJECTDN: return DnComponents.getDnIdFromDnName(dnComponent);
        case DNFieldExtractor.TYPE_SUBJECTALTNAME: return DnComponents.getDnIdFromAltName(dnComponent);
        case DNFieldExtractor.TYPE_SUBJECTDIRATTR: return DnComponents.getDnIdFromDirAttr(dnComponent);
        default: throw new IllegalArgumentException("Invalid DN type " + dnType);
        }
    }
    
    /** The only DN components that are allowed to be used in multi-value RDNs, to prevent users from 
     * making horrible mistakes like a multi-value RDN like 'O=PrimeKey+Tech' */
    static final List<ASN1ObjectIdentifier> allowedMulti = new ArrayList<>(Arrays.asList(
            CeSecoreNameStyle.CN, 
            CeSecoreNameStyle.SERIALNUMBER,
            CeSecoreNameStyle.SURNAME,
            CeSecoreNameStyle.UID,
            CeSecoreNameStyle.GIVENNAME,
            CeSecoreNameStyle.DN_QUALIFIER)
            );


    /**
     * Fills the dnfields variable with dn (or altname or subject dir attrs) numerical IDs and the value of the components 
     * (i.e. the value of CN). Also populates fieldnumbers with number of occurrences in dn
     * 
     * @param dninput the DN we want to process for example CN=Tomas,O=PrimeKey,C=SE
     * @param type one of the constants {@link #TYPE_SUBJECTDN}, {@link #TYPE_SUBJECTALTNAME}, {@link #TYPE_SUBJECTDIRATTR}
     * @throws IllegalArgumentException if DN is multi-valued but has multi-values that are not one on {@link #allowedMulti} 
     */
    public final void setDN(final String dninput, final int type) throws IllegalArgumentException {
        this.type = type;
        final ArrayList<Integer> ids;
        if (type == TYPE_SUBJECTDN) {
            ids = DnComponents.getDnDnIds();
        } else if (type == TYPE_SUBJECTALTNAME) {
            ids = DnComponents.getAltNameDnIds();
        } else if (type == TYPE_SUBJECTDIRATTR) {
            ids = DnComponents.getDirAttrDnIds();
        } else {
            ids = new ArrayList<>();
        }
        fieldnumbers = new HashMap<>();
        for(Integer id : ids) {
            fieldnumbers.put(id, 0);
        }

        String dn = dninput;
        // An empty DN, or using the DN "null" is a "no DN", don't try to parse it 
        if ((StringUtils.isNotEmpty(dn)) && !dn.equalsIgnoreCase("null")) {
            try {
                if (type == TYPE_SUBJECTDN) {
                    // Check if there are multi value RDNs
                    RDN[] rdns = IETFUtils.rDNsFromString(dn, CeSecoreNameStyle.INSTANCE);
                    final X500NameBuilder nameBuilder = new X500NameBuilder(CeSecoreNameStyle.INSTANCE);
                    boolean hasMultiValue = false;
                    for (RDN rdn : rdns) {
                        if (rdn.isMultiValued()) {
                            hasMultiValue = true;
                            // If DN is multi valued we will split it up and create a non-multi-value DN string, in order to make it easy to validate the different 
                            // fields against required fields and validators in an EE profile
                            hasMultiValueRDN = true;
                            AttributeTypeAndValue avas[] = rdn.getTypesAndValues();
                            for (AttributeTypeAndValue ava : avas) {
                                // We only allow a subset of DN attributes to be multi-valued however
                                if (!allowedMulti.contains(ava.getType())) {
                                    throw new IllegalArgumentException("A DN is not allowed to contain a multi value RDN of type: "+ava.getType().getId());
                                }
                                nameBuilder.addRDN(ava);
                            }
                        } else {
                            AttributeTypeAndValue ava = rdn.getFirst();
                            nameBuilder.addRDN(ava);
                        }
                    }
                    if (hasMultiValue) {
                        // No need to waste time on this if we didn't have any multi values, we spent enough time above already
                        final X500Name x500Name = nameBuilder.build();
                        dn = x500Name.toString();
                        if (log.isDebugEnabled()) {
                            log.debug("Exploded DN with multi-value RDN from '"+dninput+"' to '"+dn+"'.");
                        }
                    }
                }
                dnfields = new HashMap<>();
                final String[] dnexploded = LDAPDN.explodeDN(dn, false);
                for (int i = 0; i < dnexploded.length; i++) {
                    boolean exists = false;
                    for(Integer id : ids) {
                        Integer number = fieldnumbers.get(id);
                        String field;
                        if (type == TYPE_SUBJECTDN) {
                            field = DnComponents.getDnExtractorFieldFromDnId(id);
                        } else if (type == TYPE_SUBJECTALTNAME) {
                            field = DnComponents.getAltNameExtractorFieldFromDnId(id);
                        } else {
                            field = DnComponents.getDirAttrExtractorFieldFromDnId(id);
                        }
                        final String dnex = dnexploded[i];
                        final String dnexupper = dnex.toUpperCase();
                        if (id == DNFieldExtractor.URI) {
                            // Fix up URI, which can have several forms
                            if (dnexupper.contains(CertTools.URI.toUpperCase(Locale.ENGLISH) + "=")) {
                                field = CertTools.URI.toUpperCase(Locale.ENGLISH) + "=";
                            }
                            if (dnexupper.contains(CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=")) {
                                field = CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=";
                            }
                        }

                        if (dnexupper.startsWith(field)) {

                            exists = true;
                            final String rdn;
                            final String tmp;
                            // LDAPDN.unescapeRDN don't like fields with just a key but no contents. Example: 'OU='
                            if (dnex.charAt(dnex.length() - 1) != '=') {
                                tmp = LDAPDN.unescapeRDN(dnex);
                            } else {
                                tmp = dnex;
                            }
                            // We don't want the CN= (or whatever) part of the RDN
                            if (tmp.toUpperCase().startsWith(field)) {
                                rdn = tmp.substring(field.length(), tmp.length());
                            } else {
                                rdn = tmp;
                            }

                            // Same code for TYPE_SUBJECTDN, TYPE_SUBJECTALTNAME and TYPE_SUBJECTDIRATTR and we will never get here
                            // if it is not one of those types
                            dnfields.put((id * BOUNDRARY) + number, rdn);

                            number++;
                            fieldnumbers.put(id, number);
                        }
                    }
                    if (!exists) {
                        existsother = true;
                    }
                }
            } catch (Exception e) {
                log.warn("setDN: ", e);
                illegal = true;
                if (type == TYPE_SUBJECTDN) {
                    dnfields.put(CN * BOUNDRARY, "Illegal DN : " + dn);
                } else if (type == TYPE_SUBJECTALTNAME) {
                    dnfields.put(RFC822NAME * BOUNDRARY, "Illegal Subjectaltname : " + dn);
                } else if (type == TYPE_SUBJECTDIRATTR) {
                    dnfields.put(PLACEOFBIRTH * BOUNDRARY, "Illegal Subjectdirectory attribute : " + dn);
                }
            }
        }
    }

    /**
     * Returns the value of a certain DN component.
     * 
     * @param field
     *            the DN component, one of the constants DNFieldExtractor.CN, ...
     * @param number
     *            the number of the component if several entries for this component exists, normally 0 fir the first
     * 
     * @return A String for example "PrimeKey" if DNFieldExtractor.O and 0 was passed, "PrimeKey" if DNFieldExtractor.DC and 0 was passed or "com" if
     *         DNFieldExtractor.DC and 1 was passed. Returns an empty String "", if no such field with the number exists.
     */
    public String getField(final int field, final int number) {
        String returnval = dnfields.get((field * BOUNDRARY) + number);

        if (returnval == null) {
            returnval = "";
        }

        return returnval;
    }

    /**
     * Returns a string representation of a certain DN component
     * 
     * @param field
     *            the DN component, one of the constants DNFieldExtractor.CN, ...
     * @return A String for example "CN=Tomas Gustavsson" if DNFieldExtractor.CN was passed, "DC=PrimeKey,DC=com" if DNFieldExtractor.DC was passed.
     *            This string is escaped so it can be used in a DN string.
     */
    public String getFieldString(final int field) {
        StringBuilder sb = new StringBuilder();
        String fieldname = DnComponents.getDnExtractorFieldFromDnId(field);
        if (type != TYPE_SUBJECTDN) {
            fieldname = DnComponents.getAltNameExtractorFieldFromDnId(field);
        }
        final int num = getNumberOfFields(field);
        for (int i = 0; i < num; i++) {
            if (sb.length() != 0) {
                sb.append(',');
            }
            sb.append(LDAPDN.escapeRDN(fieldname + getField(field, i)));
        }
        return sb.toString();
    }

    /**
     * Function that returns true if non standard DN field exists in dn string.
     * 
     * @return true if non standard DN field exists, false otherwise
     */
    public boolean existsOther() {
        return existsother;
    }

    /**
     * Returns the number of one kind of dn field.
     * 
     * @param field
     *            the DN component, one of the constants DNFieldExtractor.CN, ...
     * 
     * @return number of components available for a field, for example 1 if DN is "dc=primekey" and 2 if DN is "dc=primekey,dc=com"
     */
    public int getNumberOfFields(final int field) {
        Integer ret = fieldnumbers.get(field);
        if (ret == null) {
            log.error("Not finding fieldnumber value for " + field);
            return 0;
        }
        return ret;
    }

    /**
     * Returns the complete array determining the number of DN components of the various types (i.e. if there are two CNs but 0 L:s etc)
     * 
     * Example, a DN with 'CN=User,O=PrimeKey,C=SE', will return:
     * (2, 1)
     * (9, 1)
     * (13, 1)
     * And all other IDs in the returned map with (id, 0)
     * 
     * @return HashMap mapping DN component field ID to number of occurrences in this DN
     */
    public HashMap<Integer, Integer> getNumberOfFields() {
        return fieldnumbers;
    }

    /** 
     * @return true if the input DN contains multi value RDNs
     */
    public boolean hasMultiValueRDN() {
        return hasMultiValueRDN;
    }

    public boolean isIllegal() {
        return illegal;
    }

}
