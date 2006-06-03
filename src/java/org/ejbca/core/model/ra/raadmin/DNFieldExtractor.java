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
 
package org.ejbca.core.model.ra.raadmin;

import java.util.ArrayList;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.ietf.ldap.LDAPDN;


/**
 * A class used to retrieve different fields from a Distiguished Name or Subject Alternate Name 
 * or Subject Directory Attributes strings.
 *
 * @author Philip Vendil
 * @version $Id: DNFieldExtractor.java,v 1.2 2006-06-03 18:10:47 anatom Exp $
 */
public class DNFieldExtractor implements java.io.Serializable {
    private static Logger log = Logger.getLogger(DNFieldExtractor.class);
    // Public constants
    public static final int TYPE_SUBJECTDN = 0;
    public static final int TYPE_SUBJECTALTNAME = 1;
    public static final int TYPE_SUBJECTDIRATTR = 2;

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
    
    // Subject Alternative Names.
    public static final int OTHERNAME = 16;
    public static final int RFC822NAME = 17;
    public static final int DNSNAME = 18;
    public static final int IPADDRESS = 19;
    public static final int X400ADDRESS = 20;
    public static final int DIRECTORYNAME = 21;
    public static final int EDIPARTNAME = 22;
    public static final int URI = 23;
    public static final int REGISTEREDID = 24;
    public static final int UPN = 25;
    public static final int GUID = 26;
    public static final int SUBJECTALTERNATIVENAMEBOUNDRARY = 16;
    
    // Subject Directory Attributes
    public static final int DATEOFBIRTH  = 27;
    public static final int PLACEOFBIRTH = 28;
    public static final int GENDER       = 29;
    public static final int COUNTRYOFCITIZENSHIP = 30;
    public static final int COUNTRYOFRESIDENCE   = 31;
    public static final int SUBJECTDIRATTRBOUNDRARY = 27;
    
    public static final int NUMBEROFFIELDS = 32;
    
    public static final String[] SUBJECTDNFIELDS = {
        "E=", "UID=", "CN=", "SN=", "GIVENNAME=", "INITIALS=", "SURNAME=", "T=", "OU=", "O=", "L=",
        "ST=", "DC=", "C=", "UNSTRUCTUREDADDRESS=", "UNSTRUCTUREDNAME="
    };
    
    public static final String[] SUBJECTALTNAME = {
        "OTHERNAME=", "RFC822NAME=", "DNSNAME=", "IPADDRESS=", "X400ADDRESS=", "DIRECTORYNAME=",
        "EDIPARTNAME=", "UNIFORMRESOURCEIDENTIFIER=", "REGISTEREDID=", "UPN=",  "GUID="
    };

    public static final String[] SUBJECTDIRATTR = {
        "DATEOFBIRTH=", "PLACEOFBIRTH=", "GENDER=", "COUNTRYOFCITIZENSHIP=", "COUNTRYOFRESIDENCE="
    };
    
    // Constants used with field ordering
    public static final int FIELDTYPE = 0;
    public static final int NUMBER = 1;

    /**
     * Creates a new instance of DNFieldExtractor
     *
     * @param dn DOCUMENT ME!
     * @param type DOCUMENT ME!
     */
    public DNFieldExtractor(String dn, int type) {
        dnfields = new HashMap();
        setDN(dn, type);
    }

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     * @param type DOCUMENT ME!
     */
    public void setDN(String dn, int type) {    	
        String[] fields;
        this.type = type;
        
        if (type == TYPE_SUBJECTDN) {        	
            fieldnumbers = new int[SUBJECTDNFIELDS.length];
            fields = SUBJECTDNFIELDS;
        } else if (type == TYPE_SUBJECTALTNAME){
            fieldnumbers = new int[SUBJECTALTNAME.length];
            fields = SUBJECTALTNAME;
        } else if (type == TYPE_SUBJECTDIRATTR){
            fieldnumbers = new int[SUBJECTDIRATTR.length];
            fields = SUBJECTDIRATTR;
        } else {
        	fields = new String[]{};
        }

        if ((dn != null) && !dn.equalsIgnoreCase("null")) {
            this.dn = dn;
            dnfields = new HashMap();

            try {
                String[] dnexploded = LDAPDN.explodeDN(dn, false);

                for (int i = 0; i < dnexploded.length; i++) {
                    boolean exists = false;                    
                    for (int j = 0; j < fields.length; j++) {
                        if (dnexploded[i].toUpperCase().startsWith(fields[j])) {
                            exists = true;
                            String rdn = LDAPDN.unescapeRDN(dnexploded[i]);
                            // We don't want the CN= (or whatever) part of the RDN
                            if (rdn.toUpperCase().startsWith(fields[j])) {
                                rdn = rdn.substring(fields[j].length(),rdn.length());                                
                            }

                            if (type == TYPE_SUBJECTDN) {
                                dnfields.put(new Integer((j * BOUNDRARY) + fieldnumbers[j]), rdn);
                            } else if (type == TYPE_SUBJECTALTNAME) {
                                dnfields.put(new Integer(((j + SUBJECTALTERNATIVENAMEBOUNDRARY) * BOUNDRARY) +
                                        fieldnumbers[j]), rdn);
                            } else if (type == TYPE_SUBJECTDIRATTR) {
                                dnfields.put(new Integer(((j + SUBJECTDIRATTRBOUNDRARY) * BOUNDRARY) +
                                        fieldnumbers[j]), rdn);
                            }
                            fieldnumbers[j]++;
                        }
                    }
                    if (!exists) {
                        existsother = true;
                    }
                }
            } catch (Exception e) {
            	log.error("setDN: ", e);
				illegal = true;
                if (type == TYPE_SUBJECTDN) {
                    dnfields.put(new Integer((CN * BOUNDRARY)), "Illegal DN : " + dn);
                } else if (type == TYPE_SUBJECTALTNAME){
                    dnfields.put(new Integer(
                            ((RFC822NAME + SUBJECTALTERNATIVENAMEBOUNDRARY) * BOUNDRARY)),
                        "Illegal Subjectaltname : " + dn);
                } else if (type == TYPE_SUBJECTDIRATTR){
                    dnfields.put(new Integer(
                            ((PLACEOFBIRTH + SUBJECTDIRATTRBOUNDRARY) * BOUNDRARY)),
                        "Illegal Subjectdirectory attribute : " + dn);
                }
            }
        } else {
            this.dn = null;
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getDN() {
        return dn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param field DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getField(int field, int number) {
        String returnval;
        returnval = (String) dnfields.get(new Integer((field * BOUNDRARY) + number));

        if (returnval == null) {
            returnval = "";
        }

        return returnval;
    }

    /**
     * Function that returns true if non standard DN field exists id dn string.
     *
     * @return DOCUMENT ME!
     */
    public boolean existsOther() {
        return existsother;
    }

    /**
     * Returns the number of one kind of dn field.
     *
     * @param field DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfFields(int field) {
        int returnval = 0;

        if (type == TYPE_SUBJECTDN) {
            returnval = fieldnumbers[field];
        } else if (type == TYPE_SUBJECTALTNAME) {
            returnval = fieldnumbers[field - OTHERNAME];
        } else if (type == TYPE_SUBJECTDIRATTR) {
            returnval = fieldnumbers[field - DATEOFBIRTH];
        }

        return returnval;
    }

    /**
     * Returns the total number of fields in dn or subject alternative name. Primary use is when
     * checking user data with it's end entity profile.
     *
     * @return DOCUMENT ME!
     */
    public int getFieldOrderLength() {
        return fieldorder.size();
    }

    /**
     * Function that returns the field with given index in original dn field. Primary use is when
     * checking user data with it's end entity profile.
     *
     * @param index DOCUMENT ME!
     *
     * @return An array of integers with the size of two, the first (0) indicating the type of
     *         field, the second (1) the current number of the field.
     */
    public int[] getFieldsInOrder(int index) {
        int[] returnval = new int[2];
        returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / BOUNDRARY;
        returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % BOUNDRARY;

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int[] getNumberOfFields() {
        return fieldnumbers;
    }

    public boolean isIllegal(){
    	return illegal;
    }

    private static final int BOUNDRARY = 100;
    private int[] fieldnumbers;
    private HashMap dnfields;
    private ArrayList fieldorder;
    private String dn;
    private boolean existsother = false;
    private boolean illegal = false;
    int type;
}
