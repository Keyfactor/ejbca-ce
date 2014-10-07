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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.cesecore.util.CeSecoreNameStyle;

/** Class holding information and utilities for handling different DN components, CN, O etc
 * 
 * This is a very complex class with lots of maps and stuff. It is because it is a first step of refactoring the DN/AltName/DirAttr handling. 
 * This previously consisted of lots of different arrays spread out all over the place, now it's gathered here in order to be able to get a view of it.
 * The underlying implementations have not changed much though, in order to still have things working, therefore there are lots of different maps and arrays, with
 * seemingly similar contents. 
 * 
 * @version $Id$
 */
public class DnComponents {
    private static Logger log = Logger.getLogger(DnComponents.class);

    /** This class should be instantiated immediately */
    private static DnComponents obj = new DnComponents();
    
    /** BC X500Name contains some lookup tables that could maybe be used here. 
     * 
     * This map is used in CertTools so sort and order DN strings so they all look the same in the database.
     * */
    private static HashMap<String, ASN1ObjectIdentifier> oids = new HashMap<String, ASN1ObjectIdentifier>();
    // Default values
    static {
        oids.put("c", CeSecoreNameStyle.C);
        oids.put("dc", CeSecoreNameStyle.DC);
        oids.put("st", CeSecoreNameStyle.ST);
        oids.put("l", CeSecoreNameStyle.L);
        oids.put("o", CeSecoreNameStyle.O);
        oids.put("ou", CeSecoreNameStyle.OU);
        oids.put("t", CeSecoreNameStyle.T);
        oids.put("surname", CeSecoreNameStyle.SURNAME);
        oids.put("initials", CeSecoreNameStyle.INITIALS);
        oids.put("givenname", CeSecoreNameStyle.GIVENNAME);
        oids.put("gn", CeSecoreNameStyle.GIVENNAME);
        oids.put("sn", CeSecoreNameStyle.SN);
        oids.put("serialnumber", CeSecoreNameStyle.SERIALNUMBER);
        oids.put("cn", CeSecoreNameStyle.CN);
        oids.put("uid", CeSecoreNameStyle.UID);
        oids.put("dn", CeSecoreNameStyle.DN_QUALIFIER);
        oids.put("emailaddress", CeSecoreNameStyle.EmailAddress);
        oids.put("e", CeSecoreNameStyle.EmailAddress);
        oids.put("email", CeSecoreNameStyle.EmailAddress);
        oids.put("unstructuredname", CeSecoreNameStyle.UnstructuredName); //unstructuredName 
        oids.put("unstructuredaddress", CeSecoreNameStyle.UnstructuredAddress); //unstructuredAddress
        oids.put("postalcode", CeSecoreNameStyle.POSTAL_CODE);
        oids.put("businesscategory", CeSecoreNameStyle.BUSINESS_CATEGORY);
        oids.put("postaladdress", CeSecoreNameStyle.POSTAL_ADDRESS);
        oids.put("telephonenumber", CeSecoreNameStyle.TELEPHONE_NUMBER);
        oids.put("pseudonym", CeSecoreNameStyle.PSEUDONYM);
        oids.put("street", CeSecoreNameStyle.STREET);
        oids.put("name", CeSecoreNameStyle.NAME);
        
    }
    /** Default values used when constructing DN strings that are put in the database
     * 
     */
    private static String[] dNObjectsForward = {
        "street", "pseudonym", "telephonenumber", "postaladdress", "businesscategory", "postalcode", "unstructuredaddress", "unstructuredname", "emailaddress", "e", "email", "dn", "uid", "cn", "name", "sn", "serialnumber", "gn", "givenname",
        "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c"
    };
    // Default values    
    private static String[] dNObjectsReverse = null;

    /**
     * These maps and constants are used in the admin-GUI and in End Entity profiles
     */

    /** These constants can be used when referring to standard, build in components 
     * 
     */
    // DN components
    public static final String DNEMAILADDRESS      = "EMAILADDRESS";
    public static final String DNQUALIFIER         = "DNQUALIFIER";
    public static final String UID                 = "UID";
    public static final String COMMONNAME          = "COMMONNAME";
    public static final String DNSERIALNUMBER      = "SERIALNUMBER";
    public static final String GIVENNAME           = "GIVENNAME";
    public static final String INITIALS            = "INITIALS";
    public static final String SURNAME             = "SURNAME";
    public static final String TITLE               = "TITLE";
    public static final String ORGANIZATIONALUNIT  = "ORGANIZATIONALUNIT";
    public static final String ORGANIZATION        = "ORGANIZATION";
    public static final String LOCALITY            = "LOCALITY";
    public static final String STATEORPROVINCE     = "STATEORPROVINCE";
    public static final String DOMAINCOMPONENT     = "DOMAINCOMPONENT";
    public static final String COUNTRY             = "COUNTRY";
    public static final String UNSTRUCTUREDADDRESS = "UNSTRUCTUREDADDRESS";
    public static final String UNSTRUCTUREDNAME    = "UNSTRUCTUREDNAME";
    public static final String POSTALCODE          = "POSTALCODE";
    public static final String BUSINESSCATEGORY    = "BUSINESSCATEGORY";
    public static final String POSTALADDRESS       = "POSTALADDRESS";
    public static final String TELEPHONENUMBER     = "TELEPHONENUMBER";
    public static final String PSEUDONYM           = "PSEUDONYM";
    public static final String STREETADDRESS       = "STREETADDRESS";
    public static final String NAME                = "NAME";
    
    // AltNames
    public static final String RFC822NAME         = "RFC822NAME";
    public static final String DNSNAME            = "DNSNAME";
    public static final String IPADDRESS          = "IPADDRESS";
    public static final String UNIFORMRESOURCEID  = "UNIFORMRESOURCEID";
    public static final String DIRECTORYNAME      = "DIRECTORYNAME";
    public static final String UPN                = "UPN";
    public static final String GUID               = "GUID";
    public static final String KRB5PRINCIPAL      = "KRB5PRINCIPAL";
    public static final String PERMANENTIDENTIFIER= "PERMANENTIDENTIFIER";
    // Below are altNames that are not implemented yet
    public static final String OTHERNAME          = "OTHERNAME";
    public static final String X400ADDRESS        = "X400ADDRESS";
    public static final String EDIPARTYNAME       = "EDIPARTYNAME";
    public static final String REGISTEREDID       = "REGISTEREDID";
    
    // Subject directory attributes
    public static final String DATEOFBIRTH         = "DATEOFBIRTH";
    public static final String PLACEOFBIRTH        = "PLACEOFBIRTH";
    public static final String GENDER              = "GENDER";
    public static final String COUNTRYOFCITIZENSHIP = "COUNTRYOFCITIZENSHIP";
    public static final String COUNTRYOFRESIDENCE  = "COUNTRYOFRESIDENCE";

    private static HashMap<String, Integer> dnNameIdMap = new HashMap<String, Integer>();
    private static HashMap<String, Integer> profileNameIdMap = new HashMap<String, Integer>();
    private static HashMap<Integer, String> dnIdToProfileNameMap = new HashMap<Integer, String>();
    private static HashMap<Integer, Integer> dnIdToProfileIdMap = new HashMap<Integer, Integer>();
    private static HashMap<Integer, Integer> profileIdToDnIdMap = new HashMap<Integer, Integer>();
    private static HashMap<Integer, String> dnErrorTextMap = new HashMap<Integer, String>();
    private static HashMap<String, String> profileNameLanguageMap = new HashMap<String, String>();
    private static HashMap<Integer, String> profileIdLanguageMap = new HashMap<Integer, String>();
    private static HashMap<Integer, String> dnIdErrorMap = new HashMap<Integer, String>();
    private static HashMap<Integer, String> dnIdToExtractorFieldMap = new HashMap<Integer, String>();
    private static HashMap<Integer, String> altNameIdToExtractorFieldMap = new HashMap<Integer, String>();
    private static HashMap<Integer, String> dirAttrIdToExtractorFieldMap = new HashMap<Integer, String>();
    private static ArrayList<String> dnProfileFields = new ArrayList<String>();
    private static final TreeSet<String> dnProfileFieldsHashSet = new TreeSet<String>();
    private static ArrayList<String> dnLanguageTexts = new ArrayList<String>();
    private static ArrayList<Integer> dnDnIds = new ArrayList<Integer>();
    private static ArrayList<String> altNameFields = new ArrayList<String>();
    private static final TreeSet<String> altNameFieldsHashSet = new TreeSet<String>();
    private static ArrayList<String> altNameLanguageTexts = new ArrayList<String>();
    private static ArrayList<Integer> altNameDnIds = new ArrayList<Integer>();
    private static ArrayList<String> dirAttrFields = new ArrayList<String>();
    private static final TreeSet<String> dirAttrFieldsHashSet = new TreeSet<String>();
    private static ArrayList<String> dirAttrLanguageTexts = new ArrayList<String>();
    private static ArrayList<Integer> dirAttrDnIds = new ArrayList<Integer>();
    private static ArrayList<String> dnExtractorFields = new ArrayList<String>();
    private static ArrayList<String> altNameExtractorFields = new ArrayList<String>();
    private static ArrayList<String> dirAttrExtractorFields = new ArrayList<String>();
    

    // Load values from a properties file, if it exists
    static {
        DnComponents.load();
    }
    
    public static ASN1ObjectIdentifier getOid(String o) {
        return oids.get(o.toLowerCase());
    }

    public static ArrayList<String> getDnProfileFields() {
    	return dnProfileFields;
    }
    public static boolean isDnProfileField(String field) {
        return dnProfileFieldsHashSet.contains(field);
    }
    public static ArrayList<String> getDnLanguageTexts() {
    	return dnLanguageTexts;
    }
    public static ArrayList<String> getAltNameFields() {
    	return altNameFields;
    }
    public static boolean isAltNameField(String field) {
        return altNameFieldsHashSet.contains(field);
    }
    public static ArrayList<String> getAltNameLanguageTexts() {
    	return altNameLanguageTexts;
    }
    public static ArrayList<String> getDirAttrFields() {
    	return dirAttrFields;
    }
    public static boolean isDirAttrField(String field) {
    	return dirAttrFieldsHashSet.contains(field);
    }
    // Used by DNFieldExtractor and EntityProfile, don't USE
    public static ArrayList<Integer> getDirAttrDnIds() {
    	return dirAttrDnIds;
    }
    // Used by DNFieldExtractor and EntityProfile, don't USE
    public static ArrayList<Integer> getAltNameDnIds() {
    	return altNameDnIds;
    }
    // Used by DNFieldExtractor and EntityProfile, don't USE
    public static ArrayList<Integer> getDnDnIds() {
    	return dnDnIds;
    }
    // Used only by DNFieldExtractor, don't USE
    protected static ArrayList<String> getDnExtractorFields() {
    	return dnExtractorFields;
    }
    protected static String getDnExtractorFieldFromDnId(int field) {
    	String val = (String)dnIdToExtractorFieldMap.get(Integer.valueOf(field));
    	return val;    	
    }
    // Used only by DNFieldExtractor, don't USE
    protected static ArrayList<String> getAltNameExtractorFields() {
    	return altNameExtractorFields;
    }
    protected static String getAltNameExtractorFieldFromDnId(int field) {
    	String val = (String)altNameIdToExtractorFieldMap.get(Integer.valueOf(field));
    	return val;    	
    }
    // Used only by DNFieldExtractor, don't USE
    protected static ArrayList<String> getDirAttrExtractorFields() {
    	return dirAttrExtractorFields;
    }
    protected static String getDirAttrExtractorFieldFromDnId(int field) {
    	String val = (String)dirAttrIdToExtractorFieldMap.get(Integer.valueOf(field));
    	return val;    	
    }
    
    public static String dnIdToProfileName(int dnid) {
    	String val = (String)dnIdToProfileNameMap.get(Integer.valueOf(dnid));
    	return val;
    }
    public static int dnIdToProfileId(int dnid) {
    	Integer val = (Integer)dnIdToProfileIdMap.get(Integer.valueOf(dnid));
    	return val.intValue();
    }
    /**
     * Method to get a language error constant for the admin-GUI from a profile name
     */
    public static String getLanguageConstantFromProfileName(String name) {
    	String ret = (String)profileNameLanguageMap.get(name);
    	return ret;
    }
    /**
     * Method to get a language error constant for the admin-GUI from a profile id
     */
    public static String getLanguageConstantFromProfileId(int id) {
    	String ret = (String)profileIdLanguageMap.get(Integer.valueOf(id));
    	return ret;
    }
    /**
     * Method to get a clear text error msg for the admin-GUI from a dn id
     */
    public static String getErrTextFromDnId(int id) {
    	String ret = (String)dnIdErrorMap.get(Integer.valueOf(id));
    	return ret;
    }
    
    
    /** This method is only used to initialize EndEntityProfile, because of legacy baggage.
     * Should be refactored sometime! Please don't use this whatever you do!
     */
    public static HashMap<String, Integer> getProfilenameIdMap() {
    	return profileNameIdMap;
    	
    }
    /** A function that takes an fieldId pointing to a corresponding id in UserView and DnFieldExctractor.
     *  For example : profileFieldIdToUserFieldIdMapper(EndEntityProfile.COMMONNAME) returns DnFieldExctractor.COMMONNAME.
     *
     *  Should only be used with subjectDN, Subject Alternative Names and subject directory attribute fields.
     */
    public static int profileIdToDnId(int profileid) {
    	Integer val = (Integer)profileIdToDnIdMap.get(Integer.valueOf(profileid));
    	if (val == null) {
    		log.error("No dn id mapping from profile id "+profileid);
    		// We allow it to fail here
    	}
    	return val.intValue();
    }

    /**
     * Returns the dnObjects (forward or reverse). 
     * ldaproder = true is the default order in EJBCA. 
     */
    public static String[]getDnObjects(boolean ldaporder) {
        if (ldaporder) {
            return dNObjectsForward;
        }
        return getDnObjectsReverse();
    }
    
    /**
     * Returns the reversed dnObjects.
     * Protected to allow testing
     */
    protected static String[] getDnObjectsReverse() {
        // Create and reverse the order if it has not been initialized already
        if (dNObjectsReverse == null) {
        	// this cast is not needed in java 5, but is needed for java 1.4
            dNObjectsReverse = (String[])dNObjectsForward.clone();
            ArrayUtils.reverse(dNObjectsReverse);
        }
        return dNObjectsReverse;
    }
    
    private static void load() {
    	loadOrdering();
    	loadMappings();
    }
    /**
     * Load DN ordering used in CertTools.stringToBCDNString etc.
     * Loads from file placed in src/dncomponents.properties
     * 
     * A line is:
     * DNName;DNid;ProfileName;ProfileId,ErrorString,LanguageConstant
     *
     */
    private static void loadMappings() {
        // Read the file to an array of lines 
        String line;
        
        BufferedReader in = null;
        InputStreamReader inf = null;
        try
        {    
            InputStream is = obj.getClass().getResourceAsStream("/profilemappings.properties");
            //log.info("is is: " + is);
            if (is != null) {
                inf = new InputStreamReader(is);
                in = new BufferedReader(inf);
                if (!in.ready()) {
                    throw new IOException();
                }
                String[] splits = null;
                int lines = 0;
                ArrayList<Integer> dnids = new ArrayList<Integer>();
                ArrayList<Integer> profileids = new ArrayList<Integer>();
                while ((line = in.readLine()) != null) {
                	if (!line.startsWith("#")) { // # is a comment line
                        splits = StringUtils.split(line, ';');
                        if ( (splits != null) && (splits.length > 5) ) {
                        	String type = splits[0];
                            String dnname = splits[1]; 
                            Integer dnid = Integer.valueOf(splits[2]); 
                            String profilename = splits[3]; 
                            Integer profileid = Integer.valueOf(splits[4]); 
                            String errstr = splits[5]; 
                            String langstr = splits[6];
                            if (dnids.contains(dnid)) {
                            	log.error("Duplicated DN Id " + dnid + " detected in mapping file.");
                            } else {
                            	dnids.add(dnid);
                            }
                            if (profileids.contains(profileid)) {
                            	log.error("Duplicated Profile Id " + profileid + " detected in mapping file.");
                            } else {
                            	profileids.add(profileid);
                            }
                            // Fill maps
                            dnNameIdMap.put(dnname, dnid);
                            profileNameIdMap.put(profilename, profileid);
                            dnIdToProfileNameMap.put(dnid, profilename);
                            dnIdToProfileIdMap.put(dnid, profileid);
                            dnIdErrorMap.put(dnid, errstr);
                            profileIdToDnIdMap.put(profileid, dnid);
                            dnErrorTextMap.put(dnid, errstr);
                            profileNameLanguageMap.put(profilename, langstr);
                            profileIdLanguageMap.put(profileid, langstr);
                            if (type.equals("DN")) {
                            	dnProfileFields.add(profilename);
                            	dnProfileFieldsHashSet.add(profilename);
                            	dnLanguageTexts.add(langstr);
                            	dnDnIds.add(dnid);
                            	dnExtractorFields.add(dnname+"=");
                            	dnIdToExtractorFieldMap.put(dnid, dnname+"=");
                            }
                            if (type.equals("ALTNAME")) {
                            	altNameFields.add(dnname);
                            	altNameFieldsHashSet.add(dnname);
                            	altNameLanguageTexts.add(langstr);
                            	altNameDnIds.add(dnid);
                            	altNameExtractorFields.add(dnname+"=");
                            	altNameIdToExtractorFieldMap.put(dnid, dnname+"=");
                            }
                            if (type.equals("DIRATTR")) {
                            	dirAttrFields.add(dnname);
                            	dirAttrFieldsHashSet.add(dnname);
                            	dirAttrLanguageTexts.add(langstr);
                            	dirAttrDnIds.add(dnid);
                            	dirAttrExtractorFields.add(dnname+"=");
                            	dirAttrIdToExtractorFieldMap.put(dnid, dnname+"=");
                            }
                            lines++;
                        }                		
                	}
                }
                in.close();
                log.debug("Read profile maps with "+lines+" lines.");
            } else {
            	throw new IOException("Input stream for /profilemappings.properties is null");
            }
        }
        catch (IOException e) {
            log.error("Can not load profile mappings: ", e);
        } finally {
            try {
                if (inf != null) {
                	inf.close();
                }
                if (in != null) {
                	in.close();                
                }
            } catch (IOException e) {}
        }

    }
    /**
     * Load DN ordering used in CertTools.stringToBCDNString etc.
     * Loads from file placed in src/dncomponents.properties
     *
     */
    private static void loadOrdering() {
        // Read the file to an array of lines 
        String line;
        LinkedHashMap<String, ASN1ObjectIdentifier> map = new LinkedHashMap<String, ASN1ObjectIdentifier>();
        BufferedReader in = null;
        InputStreamReader inf = null;
        try
        {    
            InputStream is = obj.getClass().getResourceAsStream("/dncomponents.properties");
            //log.info("is is: " + is);
            if (is != null) {
                inf = new InputStreamReader(is);
                //inf = new FileReader("c:\\foo.properties");
                in = new BufferedReader(inf);
                if (!in.ready()) {
                    throw new IOException();
                }
                String[] splits = null;
                while ((line = in.readLine()) != null) {
                	if (!line.startsWith("#")) { // # is a comment line
                		splits = StringUtils.split(line, '=');
                		if ( (splits != null) && (splits.length > 1) ) {
                			String name = splits[0].toLowerCase(); 
                			ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(splits[1]);
                			map.put(name, oid);
                		}
                	}
                }
                in.close();
                // Now we have read it in, transfer it to the main oid map
                log.info("Using DN components from properties file");
                oids.clear();
                oids.putAll(map);
                Set<String> keys = map.keySet();
                // Set the maps to the desired ordering
                dNObjectsForward = (String[])keys.toArray(new String[keys.size()]);                
            } else {
                log.debug("Using default values for DN components");                
            }
        }
        catch (IOException e) {
            log.debug("Using default values for DN components");
        } finally {
            try {
                if (inf != null) {
                	inf.close();
                }
                if (in != null) {
                	in.close();                
                }
            } catch (IOException e) {}
        }

    }

}
