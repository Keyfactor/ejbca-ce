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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ietf.ldap.LDAPDN;

/**
 * A class used to retrieve different fields from a Distinguished Name or Subject Alternate Name or Subject Directory Attributes strings.
 * 
 * @version $Id$
 */
public class DNFieldExtractor implements java.io.Serializable {

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
    private int type;

    public int getType() {
        return type;
    }
    
    /**
     * Creates a new instance of DNFieldExtractor
     * 
     * @param dn
     *            DOCUMENT ME!
     * @param type
     *            DOCUMENT ME!
     */
    public DNFieldExtractor(final String dn, final int type) {
        dnfields = new HashMap<>();
        setDN(dn, type);
    }

    /**
     * Fields that can be selected in Certificate profile and Publisher
     */
    public static Integer[] getUseFields(final int type) {
        if (type == DNFieldExtractor.TYPE_SUBJECTDN) {
            return DnComponents.getDnDnIds().toArray(new Integer[0]);
        } else if (type == DNFieldExtractor.TYPE_SUBJECTALTNAME) {
            return DnComponents.getAltNameDnIds().toArray(new Integer[0]);
        } else if (type == DNFieldExtractor.TYPE_SUBJECTDIRATTR) {
            return DnComponents.getDirAttrDnIds().toArray(new Integer[0]);
        } else {
            return new Integer[0];
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
        default: throw new IllegalStateException("Invalid DN type");
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
     * @param field Component, e.g. "CN". Not case sensitive.
     * @param dnType DN type, e.g. DNFieldExtractor.TYPE_SUBJECTDN
     * @return DN Id, or null if no such component exists for the given DN type.
     */
    public static Integer getDnIdFromComponent(final String dnComponent, final int dnType) {
        switch (dnType) {
        case DNFieldExtractor.TYPE_SUBJECTDN: return DnComponents.getDnIdFromDnName(dnComponent);
        case DNFieldExtractor.TYPE_SUBJECTALTNAME: return DnComponents.getDnIdFromAltName(dnComponent);
        case DNFieldExtractor.TYPE_SUBJECTDIRATTR: DnComponents.getDnIdFromDirAttr(dnComponent);
        default: throw new IllegalStateException("Invalid DN type");
        }
    }

    /**
     * Fills the dnfields variable with dn (or altname or subject dir attrs) numerical ids and the value of the components 
     * (i.e. the value of CN). Also populates fieldnumbers with number of occurances in dn
     * 
     * @param dn
     *            DOCUMENT ME!
     * @param type
     *            DOCUMENT ME!
     */
    public final void setDN(final String dn, final int type) {

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

        if ((dn != null) && !dn.equalsIgnoreCase("null")) {
            dnfields = new HashMap<>();
            try {
                final String[] dnexploded = LDAPDN.explodeDN(dn, false);
                for (int i = 0; i < dnexploded.length; i++) {
                    boolean exists = false;

                    for(Integer id : ids) {
                        Integer number = fieldnumbers.get(id);
                        String field;
                        if (type == TYPE_SUBJECTDN) {
                            field = DnComponents.getDnExtractorFieldFromDnId(id.intValue());
                        } else if (type == TYPE_SUBJECTALTNAME) {
                            field = DnComponents.getAltNameExtractorFieldFromDnId(id.intValue());
                        } else {
                            field = DnComponents.getDirAttrExtractorFieldFromDnId(id.intValue());
                        }
                        final String dnex = dnexploded[i].toUpperCase();
                        if (id.intValue() == DNFieldExtractor.URI) {
                            // Fix up URI, which can have several forms
                            if (dnex.indexOf(CertTools.URI.toUpperCase(Locale.ENGLISH) + "=") > -1) {
                                field = CertTools.URI.toUpperCase(Locale.ENGLISH) + "=";
                            }
                            if (dnex.indexOf(CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=") > -1) {
                                field = CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=";
                            }
                        }
                       
                        if (dnex.startsWith(field)) {
                           
                            exists = true;
                            final String rdn;
                            final String tmp;
                            // LDAPDN.unescapeRDN don't like fields with just a key but no contents. Example: 'OU='
                            if (dnexploded[i].charAt(dnexploded[i].length() - 1) != '=') {
                                tmp = LDAPDN.unescapeRDN(dnexploded[i]);
                            } else {
                                tmp = dnexploded[i];
                            }
                            // We don't want the CN= (or whatever) part of the RDN
                            if (tmp.toUpperCase().startsWith(field)) {
                                rdn = tmp.substring(field.length(), tmp.length());
                            } else {
                                rdn = tmp;
                            }

                            // Same code for TYPE_SUBJECTDN, TYPE_SUBJECTALTNAME and TYPE_SUBJECTDIRATTR and we will never get here
                            // if it is not one of those types
                            dnfields.put(Integer.valueOf((id.intValue() * BOUNDRARY) + number.intValue()), rdn);
                            
                            number = Integer.valueOf(number.intValue() + 1);
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
                    dnfields.put(Integer.valueOf((CN * BOUNDRARY)), "Illegal DN : " + dn);
                } else if (type == TYPE_SUBJECTALTNAME) {
                    dnfields.put(Integer.valueOf((RFC822NAME * BOUNDRARY)), "Illegal Subjectaltname : " + dn);
                } else if (type == TYPE_SUBJECTDIRATTR) {
                    dnfields.put(Integer.valueOf((PLACEOFBIRTH * BOUNDRARY)), "Illegal Subjectdirectory attribute : " + dn);
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
        String returnval = dnfields.get(Integer.valueOf((field * BOUNDRARY) + number));

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
        String retval = "";
        String fieldname = DnComponents.getDnExtractorFieldFromDnId(field);
        if (type != TYPE_SUBJECTDN) {
            fieldname = DnComponents.getAltNameExtractorFieldFromDnId(field);
        }
        final int num = getNumberOfFields(field);
        for (int i = 0; i < num; i++) {
            if (retval.length() == 0) {
                retval += LDAPDN.escapeRDN(fieldname + getField(field, i));
            } else {
                retval += "," + LDAPDN.escapeRDN(fieldname + getField(field, i));
            }
        }
        return retval;
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
     * @return number of componenets available for a fiels, for example 1 if DN is "dc=primekey" and 2 if DN is "dc=primekey,dc=com"
     */
    public int getNumberOfFields(final int field) {
        Integer ret = fieldnumbers.get(Integer.valueOf(field));
        if (ret == null) {
            log.error("Not finding fieldnumber value for " + field);
            ret = Integer.valueOf(0);
        }
        return ret.intValue();
    }

    /**
     * Returns the complete array determining the number of DN components of the various types (i.e. if there are two CNs but 0 Ls etc)
     * 
     * TODO: DOCUMENT
     * 
     * @return DOCUMENT ME!
     */
    public HashMap<Integer, Integer> getNumberOfFields() {
        return fieldnumbers;
    }

    public boolean isIllegal() {
        return illegal;
    }

}
