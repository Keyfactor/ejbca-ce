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
 
package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.Base64;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * The model representation of an end entity profile.
 * 
 * The algorithm for constants in the EndEntityProfile is:
 * Values are stored as 100*parameternumber+parameter, so the first COMMONNAME value is 105, the second 205 etc.
 * Use flags are stored as 10000+100*parameternumber+parameter, so the first USE_COMMONNAME value is 10105, the second 10205 etc.
 * Required flags are stored as 20000+100*parameternumber+parameter, so the first REQUIRED_COMMONNAME value is 20105, the second 20205 etc.
 * Modifyable flags are stored as 30000+100*parameternumber+parameter, so the first MODIFYABLE_COMMONNAME value is 30105, the second 30205 etc.
 *
 * Parsing an exported End Entity Profile XML (or from the getProfile method in the web service):
 * The End Entity Profile XML data is encoded using the standard Java XMLEncoder. To decode it you can use the SecureXMLDecoder class,
 * which is part of CESeCore. The result will be a Map<Object,Object>.
 * 
 * In the map there's for example a field SUBJECTDNFIELDORDER which contains a list of defined DN components, as integers. 
 * The algorithm is:
 * 100*parameter + index
 * 
 * So for example if SUBJECTDNFIELDORDER contains the two values "500, 1100" this means there is one CN and one OU. 
 * Numbers are defined in src/java/profilemappings.properties and CN=5 and OU=11, so 100*5+0 = 500 and 100*11+0 = 1100.
 * If there would be two OU fields there would also be one 1101 (100*11+1) in the SUBJECTDNFIELDORDER.
 *
 * For getting more detailed information (e.g. whether the field is required) or to look up a non-DN field (such as username), you will need to compute
 * and index and get that key from the map (instead of SUBJECTDNFIELDORDER). For example you can see if the first
 * CN field is required by finding a key in the XML with the formula:
 * 20000+100*0+5 = 20005
 * if the value of this key is true, the first CN field is required and not optional.
 * etc, for the second CN field (if there was a second one in SUBJECTDNFIELDORDER) it would be 20000+100*1+5.
 * 
 * Instead of 20000 you may use the values X*10000 where X may be (0 = value, 1 = use, 2 = required, 3 = modifiable, 4 = validation regexp).
 * If you want to access a field which is not a DN field, see the "dataConstants.put" lines below (e.g. Available CAs = 38)
 *
 * @version $Id$
 */
public class EndEntityProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {

    private static final Logger log = Logger.getLogger(EndEntityProfile.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final float LATEST_VERSION = 15;

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8356152324295231463L;
    
    /** Constant values for end entity profile. */
    private static final HashMap<String, Integer> dataConstants = new HashMap<>();

    // Field constants, used in the map below. Please use the getters/setters instead when possible!
    private static final String USERNAME           = "USERNAME";
    private static final String PASSWORD           = "PASSWORD";
    public static final String CLEARTEXTPASSWORD  = "CLEARTEXTPASSWORD";
    private static final String AUTOGENPASSWORDTYPE   = "AUTOGENPASSWORDTYPE";
    private static final String AUTOGENPASSWORDLENGTH = "AUTOGENPASSWORDLENGTH";
    
    public static final String EMAIL              = "EMAIL";
    private static final String DESCRIPTION        = "DESCRIPTION";
    public static final String KEYRECOVERABLE     = "KEYRECOVERABLE";
    public static final String DEFAULTCERTPROFILE = "DEFAULTCERTPROFILE";
    /** A list of available certificate profile names can be retrieved with getAvailableCertificateProfileNames() */
    public static final String AVAILCERTPROFILES  = "AVAILCERTPROFILES";
    public static final String DEFKEYSTORE        = "DEFKEYSTORE";
    public static final String AVAILKEYSTORE      = "AVAILKEYSTORE";
    public static final String DEFAULTTOKENISSUER = "DEFAULTTOKENISSUER";
    public static final String AVAILTOKENISSUER   = "AVAILTOKENISSUER";
    public static final String SENDNOTIFICATION   = "SENDNOTIFICATION";
    public static final String CARDNUMBER         = "CARDNUMBER";
    public static final String DEFAULTCA          = "DEFAULTCA";
    public static final String AVAILCAS           = "AVAILCAS";
    public static final String STARTTIME          = ExtendedInformation.CUSTOM_STARTTIME;	//"STARTTIME"
    public static final String ENDTIME            = ExtendedInformation.CUSTOM_ENDTIME;	//"ENDTIME"
    private static final String CERTSERIALNR       = "CERTSERIALNR";
    private static final String NAMECONSTRAINTS_PERMITTED = "NAMECONSTRAINTS_PERMITTED";
    private static final String NAMECONSTRAINTS_EXCLUDED  = "NAMECONSTRAINTS_EXCLUDED";
    /** A maximum value of the (optional) counter specifying how many certificate requests can be processed
     * before user is finalized (status set to GENERATED). Counter is only used when finishUser is
     * enabled in the CA (by default it is)
     */
    public static final String ALLOWEDREQUESTS    = "ALLOWEDREQUESTS";
    /** A revocation reason that will be applied immediately to certificates issued to a user. With this we can issue
     * a certificate that is "on hold" directly when the user gets the certificate.
     */
    public static final String ISSUANCEREVOCATIONREASON = "ISSUANCEREVOCATIONREASON";
    
    public static final String MAXFAILEDLOGINS	 = "MAXFAILEDLOGINS";

    /** Minimum password strength in bits */
    private static final String MINPWDSTRENGTH    = "MINPWDSTRENGTH";
    
    /** CA/B Forum Organization Identifier extension */
    private static final String CABFORGANIZATIONIDENTIFIER = "CABFORGANIZATIONIDENTIFIER";

    // Default values
    // These must be in a strict order that can never change 
    // Custom values configurable in a properties file (profilemappings.properties)
    static {
    	dataConstants.put(USERNAME, 0);
    	dataConstants.put(PASSWORD, 1);
    	dataConstants.put(CLEARTEXTPASSWORD, 2);
    	dataConstants.put(AUTOGENPASSWORDTYPE, 95);
    	dataConstants.put(AUTOGENPASSWORDLENGTH, 96);
        // DN components
    
    	dataConstants.put(EMAIL, 26);
    	dataConstants.put(KEYRECOVERABLE, 28);
    	dataConstants.put(DEFAULTCERTPROFILE, 29);
    	dataConstants.put(AVAILCERTPROFILES, 30);
    	dataConstants.put(DEFKEYSTORE, 31);
    	dataConstants.put(AVAILKEYSTORE, 32);
    	dataConstants.put(DEFAULTTOKENISSUER, 33);
    	dataConstants.put(AVAILTOKENISSUER, 34);
    	dataConstants.put(SENDNOTIFICATION, 35);

    	dataConstants.put(DEFAULTCA, 37);
    	dataConstants.put(AVAILCAS, 38);
    	
    	// Load all DN, altName and directoryAttributes from DnComponents.
    	dataConstants.putAll(DnComponents.getProfilenameIdMap());
    	
    	dataConstants.put(ISSUANCEREVOCATIONREASON, 94);
    	dataConstants.put(ALLOWEDREQUESTS, 97);
    	dataConstants.put(STARTTIME, 98);
    	dataConstants.put(ENDTIME, 99);
    	dataConstants.put(CARDNUMBER, 91);
    	dataConstants.put(MAXFAILEDLOGINS, 93);
    	dataConstants.put(CERTSERIALNR, 92);
    	dataConstants.put(MINPWDSTRENGTH, 90);
    	dataConstants.put(NAMECONSTRAINTS_PERMITTED, 89);
    	dataConstants.put(NAMECONSTRAINTS_EXCLUDED, 88);
    	dataConstants.put(CABFORGANIZATIONIDENTIFIER, 87);
    }
	// The max value in dataConstants (we only want to do this once)
    private static final int dataConstantsMaxValue = Collections.max(dataConstants.values());
    // The keys used when we create an empty profile (we only want to do this once)
    private static final List<String> dataConstantsUsedInEmpty = new LinkedList<>(dataConstants.keySet());
    static {
    	dataConstantsUsedInEmpty.remove(SENDNOTIFICATION);
    	dataConstantsUsedInEmpty.remove(DnComponents.OTHERNAME);
    	dataConstantsUsedInEmpty.remove(DnComponents.X400ADDRESS);
    	dataConstantsUsedInEmpty.remove(DnComponents.EDIPARTYNAME);
    }

    // Type of data constants.
    private static final int VALUE      = 0;
    private static final int USE        = 1;
    private static final int ISREQUIRED = 2;
    private static final int MODIFYABLE = 3;
    private static final int VALIDATION = 4;
    private static final int COPY       = 5;

    // Private Constants.
    private static final int FIELDBOUNDRARY  = 10000;
    private static final int NUMBERBOUNDRARY = 100;
    
    // Pre-calculated constants
    private static final int FIELDBOUNDRARY_VALUE  = FIELDBOUNDRARY * VALUE;
    private static final int FIELDBOUNDRARY_USE  = FIELDBOUNDRARY * USE;
    private static final int FIELDBOUNDRARY_ISREQUIRED  = FIELDBOUNDRARY * ISREQUIRED;
    private static final int FIELDBOUNDRARY_MODIFYABLE  = FIELDBOUNDRARY * MODIFYABLE;
    private static final int FIELDBOUNDRARY_VALIDATION  = FIELDBOUNDRARY * VALIDATION;
    private static final int FIELDBOUNDRARY_COPY  = FIELDBOUNDRARY * COPY;

    public static final String SPLITCHAR       = ";";

    public static final String TRUE  = "true";
    public static final String FALSE = "false";

    // Constants used with field ordering
    public static final int FIELDTYPE = 0;
    public static final int NUMBER    = 1;


    /** Number array keeps track of how many fields there are of a specific type, for example 2 OranizationUnits, 0 TelephoneNumber */
    private static final String NUMBERARRAY               = "NUMBERARRAY";
    private static final String SUBJECTDNFIELDORDER       = "SUBJECTDNFIELDORDER";
    private static final String SUBJECTALTNAMEFIELDORDER  = "SUBJECTALTNAMEFIELDORDER";
    private static final String SUBJECTDIRATTRFIELDORDER  = "SUBJECTDIRATTRFIELDORDER";
    
    private static final String USERNOTIFICATIONS         = "USERNOTIFICATIONS";

    private static final String REUSECERTIFICATE = "REUSECERTIFICATE";
    private static final String REVERSEFFIELDCHECKS = "REVERSEFFIELDCHECKS"; 
    private static final String ALLOW_MERGEDN_WEBSERVICES = "ALLOW_MERGEDN_WEBSERVICES";
    private static final String ALLOW_MULTI_VALUE_RDNS = "ALLOW_MULTI_VALUE_RDNS";
    
    private static final String PRINTINGUSE            = "PRINTINGUSE";
    private static final String PRINTINGDEFAULT        = "PRINTINGDEFAULT";
    private static final String PRINTINGREQUIRED       = "PRINTINGREQUIRED";
    private static final String PRINTINGCOPIES         = "PRINTINGCOPIES";
    private static final String PRINTINGPRINTERNAME    = "PRINTINGPRINTERNAME";
    private static final String PRINTINGSVGFILENAME    = "PRINTINGSVGFILENAME";
    private static final String PRINTINGSVGDATA        = "PRINTINGSVGDATA";

    private static final String PSD2QCSTATEMENT    = "PSD2QCSTATEMENT";
    
    /** 
     * If it should be possible to add/edit certificate extension data
     * when adding/editing an end entity using the admin web or not.
     */
    private static final String USEEXTENSIONDATA       = "USEEXTENSIONDATA";

    // String constants that never change, so we can do the String concat/conversion once
    private static final String CONST_DEFAULTCERTPROFILE = Integer.toString(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    private static final String CONST_AVAILCERTPROFILES1 =
            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER + ";" + 
            CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER + ";" +
            CertificateProfileConstants.CERTPROFILE_FIXED_SERVER;
    private static final String CONST_DEFKEYSTORE = Integer.toString(SecConst.TOKEN_SOFT_BROWSERGEN);
    private static final String CONST_AVAILKEYSTORE = SecConst.TOKEN_SOFT_BROWSERGEN + ";" + SecConst.TOKEN_SOFT_P12 +  ";" + SecConst.TOKEN_SOFT_JKS + ";" + SecConst.TOKEN_SOFT_PEM;
    private static final String CONST_AVAILCAS = Integer.toString(SecConst.ALLCAS);
    private static final String CONST_ISSUANCEREVOCATIONREASON = Integer.toString(RevokedCertInfo.NOT_REVOKED);
    private static final String CONST_AVAILCERTPROFILES2 =
            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER + ";" +
            CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA + ";" +
            CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
    
    /** Creates a new instance of EndEntity Profile with the default fields set. */
    public EndEntityProfile() {
    	super();
    	init(false);
    }

    /** Creates a default empty end entity profile with all standard fields added to it. */
    public EndEntityProfile(final boolean emptyprofile){
    	super();
    	init(emptyprofile);
    }

    /** Creates a new instance of EndEntity Profile used during cloning or when we load all the data from the database. */
    @SuppressWarnings("unused")
    public EndEntityProfile(final int unused) {
    }

    private void init(final boolean emptyprofile){
        if (log.isDebugEnabled()) {
        	log.debug("The highest number in dataConstants is: " + dataConstantsMaxValue);
        }
        // Common initialization of profile
        final List<Integer> numberoffields = new ArrayList<>(dataConstantsMaxValue);
        Collections.fill(numberoffields, 0);
        data.put(NUMBERARRAY, numberoffields);
        data.put(SUBJECTDNFIELDORDER, new ArrayList<Integer>());
        data.put(SUBJECTALTNAMEFIELDORDER, new ArrayList<Integer>());
        data.put(SUBJECTDIRATTRFIELDORDER, new ArrayList<Integer>());
        
        if (emptyprofile) {
        	for (final String key : dataConstantsUsedInEmpty) {
        		addFieldWithDefaults(key, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
        	}
        	// Add another DC-field since (if used) more than one is always used
    		addFieldWithDefaults(DnComponents.DOMAINCOMPONENT, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
            // Add another SAN DNSname field, for the server certificates (ref. RFC 6125)
            addFieldWithDefaults(DnComponents.DNSNAME, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
        	// Set required fields
        	setRequired(USERNAME,0,true);
        	setRequired(PASSWORD,0,true);
        	setRequired(DnComponents.COMMONNAME,0,true);
        	setRequired(DEFAULTCERTPROFILE,0,true);
        	setRequired(AVAILCERTPROFILES,0,true);
        	setRequired(DEFKEYSTORE,0,true);
        	setRequired(AVAILKEYSTORE,0,true);
        	setRequired(DEFAULTCA,0,true);
        	setRequired(AVAILCAS,0,true);
        	setRequired(ISSUANCEREVOCATIONREASON,0,false);
        	setRequired(STARTTIME,0,false);
        	setRequired(ENDTIME,0,false);
        	setRequired(ALLOWEDREQUESTS,0,false);
        	setRequired(CARDNUMBER,0,false);
        	setRequired(MAXFAILEDLOGINS,0,false);
        	setRequired(NAMECONSTRAINTS_EXCLUDED,0,false);
        	setRequired(NAMECONSTRAINTS_PERMITTED,0,false);
        	setRequired(CABFORGANIZATIONIDENTIFIER,0,false);
        	setValue(DEFAULTCERTPROFILE,0, CONST_DEFAULTCERTPROFILE);
        	setValue(AVAILCERTPROFILES,0, CONST_AVAILCERTPROFILES1);
        	setValue(DEFKEYSTORE,0, CONST_DEFKEYSTORE);
        	setValue(AVAILKEYSTORE,0, CONST_AVAILKEYSTORE);
        	setValue(AVAILCAS,0, CONST_AVAILCAS);
        	setValue(ISSUANCEREVOCATIONREASON, 0, CONST_ISSUANCEREVOCATIONREASON);
        	// Do not use hard token issuers by default.
        	setUse(AVAILTOKENISSUER, 0, false);
        	setUse(STARTTIME,0,false);
        	setUse(ENDTIME,0,false);
        	setUse(ALLOWEDREQUESTS,0,false);
        	setUse(CARDNUMBER,0,false);
        	setUse(ISSUANCEREVOCATIONREASON,0,false);
        	setUse(MAXFAILEDLOGINS,0,false);
            setValue(MAXFAILEDLOGINS, 0, Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS));
        	setUse(MINPWDSTRENGTH,0,false);
        	setUse(NAMECONSTRAINTS_PERMITTED,0,false);
        	setUse(NAMECONSTRAINTS_EXCLUDED,0,false);
        	setUse(CABFORGANIZATIONIDENTIFIER,0,false);
        } else {
        	// initialize profile data
        	addFieldWithDefaults(USERNAME, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(PASSWORD, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addField(AUTOGENPASSWORDTYPE);
        	addFieldWithDefaults(AUTOGENPASSWORDLENGTH, "8", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(DnComponents.COMMONNAME, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addField(EMAIL);
        	addFieldWithDefaults(DEFAULTCERTPROFILE, CONST_DEFAULTCERTPROFILE, Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(AVAILCERTPROFILES, CONST_AVAILCERTPROFILES2, Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(DEFKEYSTORE, CONST_DEFKEYSTORE, Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(AVAILKEYSTORE, CONST_AVAILKEYSTORE, Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addField(DEFAULTTOKENISSUER);
        	// Do not use hard token issuers by default.
        	addFieldWithDefaults(AVAILTOKENISSUER, "", Boolean.TRUE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(AVAILCAS, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(DEFAULTCA, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
        	addFieldWithDefaults(STARTTIME, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(ENDTIME, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(ALLOWEDREQUESTS, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(CARDNUMBER, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(ISSUANCEREVOCATIONREASON, CONST_ISSUANCEREVOCATIONREASON, Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(MAXFAILEDLOGINS, Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS), Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(NAMECONSTRAINTS_PERMITTED, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(NAMECONSTRAINTS_EXCLUDED, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        	addFieldWithDefaults(CABFORGANIZATIONIDENTIFIER, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
        }
    }

    /** Add a field with value="", required=false, use=true, modifyable=true, if the parameter exists, ignored otherwise */
    public void addField(final String parameter){
        final int num = getParameterNumber(parameter);
        if (num > 0) {
            addField(num, parameter);
        } else {
            log.debug("Parameter does not exist (0 returned as parameter number; "+parameter);
        }
    }
    
    /**
     * Function that adds a field to the profile.
     *
     * @param parameter is the field and one of the field constants.
     */
    public void addField(final int parameter){
    	addField(parameter, getParameter(parameter));
    }
    
    /** Add a field with value="", required=false, use=true, modifyable=true, copy =false  */
    private void addField(final int parameter, final String parameterName) {
    	addFieldWithDefaults(parameter, parameterName, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE, Boolean.FALSE, null);
    }
    
    private void addFieldWithDefaults(final String parameterName, final String value, final Boolean required, final Boolean use, final Boolean modifyable) {
        addFieldWithDefaults(getParameterNumber(parameterName), parameterName, value, required, use, modifyable, Boolean.FALSE, null);
    }

    private void addFieldWithDefaults(final int parameter, final String parameterName, final String value, final Boolean required, final Boolean use, final Boolean modifyable, boolean copy, final LinkedHashMap<String,Object> validation) {
    	final int size = getNumberOfField(parameter);
    	// Perform operations directly on "data" to save some cycles..
    	final int offset = (NUMBERBOUNDRARY*size) + parameter;
   		data.put(FIELDBOUNDRARY_VALUE + offset, value);
    	data.put(FIELDBOUNDRARY_ISREQUIRED + offset, required);
    	data.put(FIELDBOUNDRARY_USE + offset, use);
    	data.put(FIELDBOUNDRARY_MODIFYABLE + offset, modifyable);
    	data.put(FIELDBOUNDRARY_COPY + offset, copy);
    	if (validation != null) {
    	    // validation should be a map of a validator class name (excluding package name) and a validator-specific object.
    	    data.put(FIELDBOUNDRARY_VALIDATION + offset, validation);
    	} else {
    	    data.remove(FIELDBOUNDRARY_VALIDATION + offset);
    	}
    	if (DnComponents.isDnProfileField(parameterName)) {
    		@SuppressWarnings("unchecked")
            final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
    		final int val = (NUMBERBOUNDRARY*parameter) + size;
    		fieldorder.add(val);
    	} else if (DnComponents.isAltNameField(parameterName)) {
    		@SuppressWarnings("unchecked")
            final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
    		final int val = (NUMBERBOUNDRARY*parameter) + size;
    		fieldorder.add(val);
    	} else if (DnComponents.isDirAttrField(parameterName)) {
    		@SuppressWarnings("unchecked")
            final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
    		final int val = (NUMBERBOUNDRARY*parameter) + size;
    		fieldorder.add(val);
    	}
    	incrementFieldnumber(parameter);
    }

    public void removeField(final String parameter, final int number){
    	removeField(getParameterNumber(parameter), number);
    }

    /**
     * Function that removes a field from the end entity profile.
     *
     * @param parameter is the field to remove.
     * @param number is the number of field.
     */
    public void removeField(final int parameter, final int number){
    	// Remove field and move all file ids above.
    	final int size = getNumberOfField(parameter);
    	if (size>0) {
    		for (int n = number; n < size-1; n++) {
    			setValue(parameter,n,getValue(parameter,n+1));
    			setRequired(parameter,n,isRequired(parameter,n+1));
    			setUse(parameter,n,getUse(parameter,n+1));
    			setModifyable(parameter,n,isModifyable(parameter,n+1));
    		}
    		final String param = getParameter(parameter);
    		// Remove last element from Subject DN order list.
    		if (DnComponents.isDnProfileField(param)) {
    			@SuppressWarnings("unchecked")
                final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
    			final Integer value = (NUMBERBOUNDRARY*parameter) + size -1;
    			fieldorder.remove(value); // must use Integer type to avoid calling remove(index) method
    		}
    		// Remove last element from Subject AltName order list.
    		if (DnComponents.isAltNameField(param)) {
    			@SuppressWarnings("unchecked")
                final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
    			final Integer value = (NUMBERBOUNDRARY*parameter) + size -1;
    			fieldorder.remove(value);
    		}
    		// Remove last element from Subject DirAttr order list.
    		if (DnComponents.isDirAttrField(param)) {
    			@SuppressWarnings("unchecked")
                final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
    			final Integer value = (NUMBERBOUNDRARY*parameter) + size -1;
    			fieldorder.remove(value);
    		}
    		// Remove last element of the type from hashmap
    		data.remove(FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY*(size-1)) + parameter);
    		data.remove(FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY*(size-1)) + parameter);
    		data.remove(FIELDBOUNDRARY_ISREQUIRED + (NUMBERBOUNDRARY*(size-1)) + parameter);
    		data.remove(FIELDBOUNDRARY_MODIFYABLE + (NUMBERBOUNDRARY*(size-1)) + parameter);
    		data.remove(FIELDBOUNDRARY_COPY + (NUMBERBOUNDRARY*(size-1)) + parameter);
    		decrementFieldnumber(parameter);
    	}
    }

    /**
     * @param parameter the name of a field from profilemappings.properties, see DnComponents
     * @return the number of one kind of field in the profile, or 0 if it does not exist.
     * @see DnComponents
     */
    public int getNumberOfField(final String parameter){
        final int num = getParameterNumber(parameter);
        if (num != -1) {
            return getNumberOfField(num);
        } else {
            return 0;
        }
    }
    /**
     * @param parameter the number of a field from profilemappings.properties
     * @return the number of one kind of field in the profile.
     */
    public int getNumberOfField(final int parameter){
    	final ArrayList<Integer> arr = checkAndUpgradeWithNewFields(parameter);
    	return arr.get(parameter);
    }

	private ArrayList<Integer> checkAndUpgradeWithNewFields(final int parameter) {
		@SuppressWarnings("unchecked")
        final ArrayList<Integer> arr = (ArrayList<Integer>)data.get(NUMBERARRAY);
    	// This is an automatic upgrade function, if we have dynamically added new fields
    	if (parameter >= arr.size()) {
    		if (log.isDebugEnabled()) {
        		log.debug(intres.getLocalizedMessage("ra.eeprofileaddfield", parameter));
    		}
    		for (int i=arr.size(); i<=parameter; i++) {
                arr.add(0);
    		}
            data.put(NUMBERARRAY,arr);
    	}
		return arr;
	}

    public void setValue(final int parameter, final int number, final String value) {
		data.put(FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY*number) + parameter, StringUtils.trim(value));
    }

    public void setValue(final String parameter, final int number, final String value) {
    	setValue(getParameterNumber(parameter), number, value);
    }

    public void setUse(final int parameter, final int number, final boolean use){
    	data.put(FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY*number) + parameter, use);
    }

    public void setUse(final String parameter, final int number, final boolean use){
    	setUse(getParameterNumber(parameter), number, use);
    }

    public void setCopy(final int parameter, final int number, final boolean copy){
        data.put(FIELDBOUNDRARY_COPY + (NUMBERBOUNDRARY*number) + parameter, copy);
    }

    public void setCopy(final String parameter, final int number, final boolean copy){
        setCopy(getParameterNumber(parameter), number, copy);
    }

    public void setRequired(final int parameter, final int number, final boolean required) {
    	data.put(FIELDBOUNDRARY_ISREQUIRED + (NUMBERBOUNDRARY*number) + parameter, required);
    }

    public void setRequired(final String parameter, final int number, final boolean required) {
    	setRequired(getParameterNumber(parameter), number, required);
    }

    public void setModifyable(final int parameter, final int number, final boolean changeable) {
    	data.put(FIELDBOUNDRARY_MODIFYABLE + (NUMBERBOUNDRARY*number) + parameter, changeable);
    }

    public void setModifyable(final String parameter, final int number, final boolean changeable) {
    	setModifyable(getParameterNumber(parameter), number, changeable);
    }
    
    public void setValidation(final int parameter, final int number, final Map<String,Serializable> validation){
        Integer paramNum = FIELDBOUNDRARY_VALIDATION + (NUMBERBOUNDRARY*number) + parameter;
        if (validation != null) {
            data.put(paramNum, new LinkedHashMap<>(validation));
        } else {
            data.remove(paramNum);
        }
    }

    public void setValidation(final String parameter, final int number, final LinkedHashMap<String,Serializable> validation){
        setValidation(getParameterNumber(parameter), number, validation);
    }

    public String getValue(final int parameter, final int number) {
    	return getValueDefaultEmpty(FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY*number) + parameter);
    }

    /**
     * Semi-internal method to get a default value, or list of allowed values.
     *
     * <p><b>Note:</b> Consider calling the appropriate getters instead of this method.
     * For example <code>getAvailableCertificateProfileIds()</code> instead of calling <code>getValue(AVAILCERTPROFILES,0)</code>
     *
     * @param parameter Field type, one of the constants defined in this class.
     * @param number Zero based index of field, if there is more than one.
     */
    public String getValue(final String parameter, final int number) {
    	return getValue(getParameterNumber(parameter), number);
    }

    /**
     * Gets a value, converted from ; separated string to a list of integers.
     * Used for lists of available CAs, certificate profiles, token types, etc... 
     * @return List of integer IDs, never null.
     * @see {@link #getValue(String, int) getValue} for a description of the parameters.
     */
    private List<Integer> getIdListValue(final String fieldType, final int number) {
        final String str = getValue(fieldType, number);
        return StringTools.idStringToListOfInteger(str, SPLITCHAR);
    }

    public boolean getUse(final int parameter, final int number){
    	return getValueDefaultFalse(FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY*number) + parameter);
    }

    /**
     * Semi-internal method to get the "use" (enabled or disabled) state of a parameter.
     * 
     * <p><b>Note:</b> Consider calling the appropriate getters instead of this method.
     * For example <code>getCustomSerialNumberUsed()</code> instead of calling <code>getUse(CERTSERIALNR, 0)</code>
     */
    public boolean getUse(final String parameter, final int number){
    	return getUse(getParameterNumber(parameter), number);
    }

    public boolean getCopy(final int parameter, final int number){
        return getValueDefaultFalse(FIELDBOUNDRARY_COPY + (NUMBERBOUNDRARY*number) + parameter);
    }

    public boolean getCopy(final String parameter, final int number){
        return getCopy(getParameterNumber(parameter), number);
    }

    public boolean isRequired(final int parameter, final int number) {
    	return getValueDefaultFalse(FIELDBOUNDRARY_ISREQUIRED + (NUMBERBOUNDRARY*number) + parameter);
    }

    /**
     * Semi-internal method to get the "is required" state of a parameter.
     * 
     * <p><b>Note:</b> Consider calling the appropriate getters instead of this method.
     * For example <code>getEmailDomainRequired()</code> instead of calling <code>isRequired(EMAIL, 0)</code>
     */
    public boolean isRequired(final String parameter, final int number) {
    	return isRequired(getParameterNumber(parameter), number);
    }

    public boolean isModifyable(final int parameter, final int number) {
    	return getValueDefaultFalse(FIELDBOUNDRARY_MODIFYABLE + (NUMBERBOUNDRARY*number) + parameter);
    }

    /**
     * Semi-internal method to get the "is modifiable" state of a parameter.
     * 
     * <p><b>Note:</b> Consider calling the appropriate getters instead of this method.
     * For example <code>getEmailDomainModifiable()</code> instead of calling <code>isModifyable(EMAIL, 0)</code>
     */
    public boolean isModifyable(final String parameter, final int number) {
    	return isModifyable(getParameterNumber(parameter), number);
    }
    
    @SuppressWarnings("unchecked")
    public LinkedHashMap<String,Serializable> getValidation(final int parameter, final int number){
        return (LinkedHashMap<String,Serializable>)data.get(FIELDBOUNDRARY_VALIDATION + (NUMBERBOUNDRARY*number) + parameter);
    }

    public LinkedHashMap<String,Serializable> getValidation(final String parameter, final int number){
        return getValidation(getParameterNumber(parameter), number);
    }

    @SuppressWarnings("unchecked")
    public int getSubjectDNFieldOrderLength(){
    	return ((ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER)).size();
    }

    @SuppressWarnings("unchecked")
    public int getSubjectAltNameFieldOrderLength(){
    	return ((ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER)).size();
    }

    @SuppressWarnings("unchecked")
    public int getSubjectDirAttrFieldOrderLength(){
        return ((ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER)).size();
    }
    
    /**
     * Returns the number of Subject DN, SAN or Subject Directory Attributes fields in this profile.
     * @param dnType DNFieldExtractor.TYPE_*
     * @return Number of fields for the given field type
     */
    public int getFieldOrderLengthForDnType(final int dnType) {
        switch (dnType) {
            case DNFieldExtractor.TYPE_SUBJECTDN: return getSubjectDNFieldOrderLength();
            case DNFieldExtractor.TYPE_SUBJECTALTNAME: return getSubjectAltNameFieldOrderLength();
            case DNFieldExtractor.TYPE_SUBJECTDIRATTR: return getSubjectDirAttrFieldOrderLength();
            default: throw new IllegalArgumentException("Invalid DN type");
        }
    }

    /** returns two int : the first is the DN field which is a constant in DN field extractor,
     * the second is in which order the attribute is, 0 is first OU and 1 can mean second OU (if OU is specified in the first value).
     * 
     */
    public int[] getSubjectDNFieldsInOrder(final int index) {
    	final int[] returnval = new int[2];
    	@SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
    	final int i = fieldorder.get(index);
    	returnval[NUMBER] = i % NUMBERBOUNDRARY;
    	returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    	return returnval;
    }

    public int[] getSubjectAltNameFieldsInOrder(final int index) {
    	int[] returnval = new int[2];
    	@SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
    	final int i = fieldorder.get(index);
    	returnval[NUMBER] = i % NUMBERBOUNDRARY;
    	returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    	return returnval;
    }

    public int[] getSubjectDirAttrFieldsInOrder(final int index) {
    	final int[] returnval = new int[2];
    	@SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder = (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
    	final int i = fieldorder.get(index);
    	returnval[NUMBER] = i % NUMBERBOUNDRARY;
    	returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    	return returnval;
    }
    
    /**
     * Returns the Subject DN, SAN or Subject Directory Attributes field of the given index in the profile.
     * @param dnType DNFieldExtractor.TYPE_*
     * @param index Zero based index of field, up to and including getFieldOrderLengthForDnType(dnType)-1.
     * @return Number of fields for the given field type
     */
    public int[] getFieldsInOrderForDnType(final int dnType, final int index) {
        switch (dnType) {
            case DNFieldExtractor.TYPE_SUBJECTDN: return getSubjectDNFieldsInOrder(index);
            case DNFieldExtractor.TYPE_SUBJECTALTNAME: return getSubjectAltNameFieldsInOrder(index);
            case DNFieldExtractor.TYPE_SUBJECTDIRATTR: return getSubjectDirAttrFieldsInOrder(index);
            default: throw new IllegalArgumentException("Invalid DN type");
        }
    }

    /** Gets a Collection of available CA Ids (as Integers). 
     *
     * @return a Collection of CA Ids (never null).
     */
    public List<Integer> getAvailableCAs(){
        return getIdListValue(AVAILCAS, 0);
    }

    /** Sets available CA ids. These are stored as a ; separated string in the end entity profile
     * 
     * @param ids Collection of CA ids
     */
    public void setAvailableCAs(Collection<Integer> ids) {
        StringBuilder builder = new StringBuilder();
        for (Integer id: ids) {
            if (builder.length() == 0) {
                builder.append(id);
            } else {
                builder.append(';').append(id);
            }
        }
        setValue(AVAILCAS,0, builder.toString());
    }

    /** Gets a Collection of available certificate profile ids
     * Use Integer.valueOf(idstring) to get the int value
     * 
     * @return a Collection of ids
     */
    public List<Integer> getAvailableCertificateProfileIds() {
        return getIdListValue(AVAILCERTPROFILES, 0);
    }

    /**
     * Like {@link #getAvailableCertificateProfileIds}, but returns the Ids as strings.
     * @deprecated Since EJBCA 7.0.0
     */
    @Deprecated
    public Collection<String> getAvailableCertificateProfileIdsAsStrings() {
        final ArrayList<String> profiles = new ArrayList<>();
        final String list = getValue(AVAILCERTPROFILES,0);
        if (list != null) {
            profiles.addAll(Arrays.asList(list.split(SPLITCHAR)));
        }
        return profiles;        
    }

    /** Sets available certificate profile ids. These are stored as a ; separated string in the end entity profile
     * 
     * @param ids Collection of certificate profile ids
     */
    public void setAvailableCertificateProfileIds(Collection<Integer> ids) {
        StringBuilder builder = new StringBuilder();
        for (Integer id: ids) {
            if (builder.length() == 0) {
                builder.append(id);
            } else {
                builder.append(';').append(id);
            }
        }
        setValue(AVAILCERTPROFILES,0, builder.toString());
    }
    
    public int getDefaultCA() {
    	int ret = -1;
    	final String str = getValue(DEFAULTCA,0);
    	if (str != null && !StringUtils.isEmpty(str)) {
    		ret = Integer.valueOf(str);
    		if (ret == CAConstants.ALLCAS) {
    		    return -1;
    		}
    	}
        return ret;
    }
    
    public void setDefaultCA(final int caId) {
        // Might get called with caId=1 (CAConstants.ALLCAS) if the CA Id is missing, and the code tries to take the first available CA (which can be "All CAs" or 1)
        setValue(EndEntityProfile.DEFAULTCA, 0, String.valueOf(caId == CAConstants.ALLCAS ? -1 : caId));
    }
    
    /** 
     * @return the certificate profileId configured as default certificate profile, or -1 if no default certificate profile exists
     */
    public int getDefaultCertificateProfile() {
        int ret = -1;
        final String str = getValue(DEFAULTCERTPROFILE,0);
        if (StringUtils.isNotEmpty(str)) {
            ret = Integer.parseInt(str);
        }
        return ret;
    }
    
    public void setDefaultCertificateProfile(final int certificateProfileId) {
        setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, String.valueOf(certificateProfileId));
    }
    
    /**
     * Returns the default token type, such as "User generated" or "PCKS#12"
     * @return One of the SecConst.TOKEN_SOFT_* constants
     */
    public int getDefaultTokenType() {
        int ret = SecConst.TOKEN_SOFT_BROWSERGEN;
        final String str = getValue(EndEntityProfile.DEFKEYSTORE, 0);
        if (StringUtils.isNotEmpty(str)) {
            ret = Integer.parseInt(str);
        }
        return ret;
    }

    /**
     * Sets the default token type, such as "User generated" or "PCKS#12"
     * @param tokenType One of the SecConst.TOKEN_SOFT_* constants
     */
    public void setDefaultTokenType(final int tokenType) {
        setValue(EndEntityProfile.DEFKEYSTORE, 0, String.valueOf(tokenType));
    }

    public List<Integer> getAvailableTokenTypes() {
        return getIdListValue(AVAILKEYSTORE, 0);
    }

    public void setAvailableTokenTypes(final Collection<Integer> tokenTypes) {
        setValue(AVAILKEYSTORE, 0, StringUtils.join(tokenTypes, SPLITCHAR));
    }
    
    public String getUsernameDefault() {
        return getValue(USERNAME, 0);
    }

    public void setUsernameDefault(final String username) {
        setValue(USERNAME, 0, username);
    }

    public boolean isUsernameRequired() {
        return isRequired(USERNAME, 0);
    }

    public boolean isAutoGeneratedUsername() {
        return !isModifyable(USERNAME, 0);
    }

    public void setAutoGeneratedUsername(final boolean autoGenerate) {
        setModifyable(USERNAME, 0, !autoGenerate);
    }

    public boolean isPasswordRequired() {
        return isRequired(PASSWORD, 0);
    }

    public void setPasswordRequired(final boolean required) {
        setRequired(PASSWORD, 0, required);
    }

    public boolean isPasswordModifiable() {
        return isModifyable(PASSWORD, 0);
    }

    public boolean useAutoGeneratedPasswd() {
    	return !getUse(PASSWORD, 0);
    }

    public void setUseAutoGeneratedPasswd(final boolean autoGenerate) {
        setUse(PASSWORD, 0, !autoGenerate);
    }

    public boolean isPasswordPreDefined() {
        return StringUtils.isNotBlank(getPredefinedPassword());
    }

    public String getPredefinedPassword() {
        return getValue(PASSWORD, 0);
    }

    public void setPredefinedPassword(final String password) {
        setValue(PASSWORD, 0, password);
    }

    /**
     * Returns the characters to be used in auto-generated passwords.
     * @return One of the constants in {@link PasswordGeneratorFactory}
     */
    public String getAutoGeneratedPasswordType() {
    	String type = getValue(AUTOGENPASSWORDTYPE, 0);
    	if (StringUtils.isEmpty(type)) {
    		type = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
    	}
    	return type;
    }

    /**
     * Sets the characters to be used in auto-generated passwords.
     * @param type One of the constants in {@link PasswordGeneratorFactory}
     */
    public void setAutoGeneratedPasswordType(final String type) {
        if (!PasswordGeneratorFactory.getAvailablePasswordTypes().contains(type)) {
            throw new IllegalArgumentException("Invalid password auto-generation type");
        }
        setValue(AUTOGENPASSWORDTYPE, 0, type);
    }

    public int getAutoGeneratedPasswordLength() {
    	final String length = getValue(AUTOGENPASSWORDLENGTH, 0);
    	int pwdlen = 8;
    	if (!StringUtils.isEmpty(length)) {
    		try {
    			pwdlen = Integer.parseInt(length);    		
    		} catch (NumberFormatException e) {
    			log.info("NumberFormatException parsing AUTOGENPASSWORDLENGTH, using default value of 8: ", e);
    		}
    	}
    	return pwdlen;
    }

    public void setAutoGeneratedPasswordLength(final int length) {
        setValue(AUTOGENPASSWORDLENGTH, 0, String.valueOf(length));
    }

    public String makeAutoGeneratedPassword() {
    	final int pwdlen = getAutoGeneratedPasswordLength();
    	return PasswordGeneratorFactory.getInstance(getAutoGeneratedPasswordType()).getNewPassword(pwdlen, pwdlen);
    }
    
    /** @return strength in bits = log2(possible chars) * number of chars rounded down */
    public int getAutoGenPwdStrength() {
    	final int numerOfDifferentChars = PasswordGeneratorFactory.getInstance(getAutoGeneratedPasswordType()).getNumerOfDifferentChars();
    	return getPasswordStrength(numerOfDifferentChars, getAutoGeneratedPasswordLength());
    }
    
    /** @return strength in bits = log2(possible chars) * number of chars rounded down */
    private int getPasswordStrength(int numerOfDifferentChars, int passwordLength) {
    	return (int) (Math.floor(Math.log(numerOfDifferentChars)/Math.log(2)) * passwordLength);
    }

    /** @return the minimum strength that a password is allowed to have in bits */
    public int getMinPwdStrength() {
    	if (!getUse(MINPWDSTRENGTH, 0)) {
    		return 0;
    	}
    	return Integer.parseInt(getValue(MINPWDSTRENGTH, 0));
    }
    
    /** Set the minimum strength that a password is allowed to have in bits */
    public void setMinPwdStrength(int minPwdStrength) {
    	this.setUse(MINPWDSTRENGTH, 0, true);
    	this.setValue(MINPWDSTRENGTH, 0, String.valueOf(minPwdStrength));
    }
    
    /**
     * @return String value with types from org.ejbca.util.passgen, example org.ejbca.util.passgen.DigitPasswordGenerator.NAME (PWGEN_DIGIT)
     */
    public static Collection<String> getAvailablePasswordTypes() {
        return PasswordGeneratorFactory.getAvailablePasswordTypes();
    }
    
    public boolean isClearTextPasswordUsed() {
        return getUse(CLEARTEXTPASSWORD, 0);
    }
    
    public void setClearTextPasswordUsed(final boolean use) {
        setUse(CLEARTEXTPASSWORD, 0, use);
    }
    
    public boolean isClearTextPasswordDefault() {
        return TRUE.equals(getValue(CLEARTEXTPASSWORD, 0));
    }
    
    public void setClearTextPasswordDefault(final boolean clearTextPasswordDefault) {
        setValue(CLEARTEXTPASSWORD, 0, String.valueOf(clearTextPasswordDefault));
    }
    
    public boolean isClearTextPasswordRequired() {
        return isRequired(CLEARTEXTPASSWORD, 0);
    }
    
    public void setClearTextPasswordRequired(final boolean required) {
        setRequired(CLEARTEXTPASSWORD, 0, required);
    }

    public boolean isEmailUsed() {
        return getUse(EMAIL, 0);
    }

    public void setEmailUsed(final boolean use) {
        setUse(EMAIL, 0, use);
    }

    /** Returns the e-mail domain, or a full e-mail address (depending on whether @ is present) */
    public String getEmailDomain() {
        return getValue(EMAIL, 0);
    }

    public void setEmailDomain(final String domain) {
        setValue(EMAIL, 0, domain);
    }

    public boolean isEmailModifiable() {
        return isModifyable(EMAIL, 0);
    }

    public void setEmailDomainModifiable(final boolean modifiable) {
        setModifyable(EMAIL, 0, modifiable);
    }

    public boolean isEmailRequired() {
        return isRequired(EMAIL, 0);
    }

    public void setEmailRequired(final boolean required) {
        setRequired(EMAIL, 0, required);
    }
    
    public String getDescription() {
        return getValue(DESCRIPTION, 0);
    }

    public void setDescription(final String description) {
        setValue(DESCRIPTION, 0, description);
    }

    public boolean isAllowedRequestsUsed() {
        return getUse(ALLOWEDREQUESTS, 0);
    }

    public void setAllowedRequestsUsed(final boolean limited) {
        setUse(ALLOWEDREQUESTS, 0, limited);
    }

    public int getAllowedRequests() {
        if (!isAllowedRequestsUsed()) {
            return 1; // only one request is allowed by default, see the "End Entity Profiles" documentation page
        }
        final String value = getValue(ALLOWEDREQUESTS, 0);
        if (StringUtils.isEmpty(value)) {
            return 1;
        }
        return Integer.valueOf(value);
    }

    public void setAllowedRequests(final int allowedRequests) {
        setValue(ALLOWEDREQUESTS, 0, String.valueOf(allowedRequests));
    }

    public boolean isMaxFailedLoginsUsed() {
        return getUse(MAXFAILEDLOGINS, 0);
    }

    public void setMaxFailedLoginsUsed(final boolean use) {
        setUse(MAXFAILEDLOGINS, 0, use);
    }

    public boolean isMaxFailedLoginsModifiable() {
        return isModifyable(MAXFAILEDLOGINS, 0);
    }

    public void setMaxFailedLoginsModifiable(final boolean modifiable) {
        setModifyable(MAXFAILEDLOGINS, 0, modifiable);
    }

    public int getMaxFailedLogins() {
        if (!getUse(MAXFAILEDLOGINS, 0)) {
            return -1;
        }
        final String value = getValue(MAXFAILEDLOGINS, 0);
        return (StringUtils.isEmpty(value) ? -1 : Integer.valueOf(value));
    }

    public void setMaxFailedLogins(final int maxFailedLogins) {
        setValue(MAXFAILEDLOGINS, 0, String.valueOf(maxFailedLogins));
    }
    
    public boolean isMaxFailedLoginsLimited() {
        return isMaxFailedLoginsUsed() && getMaxFailedLogins() != -1;
    }

    public boolean isIssuanceRevocationReasonUsed() {
        return getUse(ISSUANCEREVOCATIONREASON, 0);
    }

    public void setIssuanceRevocationReasonUsed(final boolean use) {
        setUse(ISSUANCEREVOCATIONREASON, 0, use);
    }

    public boolean isIssuanceRevocationReasonModifiable() {
        return isModifyable(ISSUANCEREVOCATIONREASON, 0);
    }

    public void setIssuanceRevocationReasonModifiable(final boolean use) {
        setModifyable(ISSUANCEREVOCATIONREASON, 0, use);
    }

    /**
     * Returns the initial revocation reason.
     * @see #isIssuanceRevocationReasonUsed
     * @return One of the {@link RevocationReasons} constants.
     */
    public RevocationReasons getIssuanceRevocationReason() {
        final String value = getValue(ISSUANCEREVOCATIONREASON, 0);
        if (value != null) {
            return RevocationReasons.getFromDatabaseValue(Integer.parseInt(value));
        } else {
            return RevocationReasons.NOT_REVOKED;
        }
    }

    /**
     * Sets the initial revocation reason.
     * @see #setIssuanceRevocationReasonUsed
     * @param reason One of the {@link RevocationReasons} constants.
     */
    public void setIssuanceRevocationReason(final RevocationReasons reason) {
        setValue(ISSUANCEREVOCATIONREASON, 0, String.valueOf(reason.getDatabaseValue()));
    }

    public boolean isCustomSerialNumberUsed() {
        return getUse(CERTSERIALNR, 0);
    }

    public void setCustomSerialNumberUsed(final boolean use) {
        setUse(CERTSERIALNR, 0, use);
    }

    public boolean isPsd2QcStatementUsed() {
        return getValueDefaultFalse(PSD2QCSTATEMENT);
    }
    
    public void setPsd2QcStatementUsed(final boolean use) {
        data.put(PSD2QCSTATEMENT, use);
    }

    public boolean isValidityStartTimeUsed() {
        return getUse(STARTTIME, 0);
    }

    public void setValidityStartTimeUsed(final boolean use) {
        setUse(STARTTIME, 0, use);
    }

    public boolean isValidityStartTimeModifiable() {
        return isModifyable(STARTTIME, 0);
    }

    public void setValidityStartTimeModifiable(final boolean modifiable) {
        setModifyable(STARTTIME, 0, modifiable);
    }

    /**
     * Optional validity start time in absolute "yyyy-MM-dd HH:mm" or relative "days:hours:minutes" format.
     * @return Start time. Never null, but may be empty.
     */
    public String getValidityStartTime() {
        return getValue(STARTTIME, 0);
    }

    public void setValidityStartTime(final String startTime) {
        setValue(STARTTIME, 0, startTime);
    }

    public boolean isValidityEndTimeUsed() {
        return getUse(ENDTIME, 0);
    }

    public void setValidityEndTimeUsed(final boolean use) {
        setUse(ENDTIME, 0, use);
    }

    public boolean isValidityEndTimeModifiable() {
        return isModifyable(ENDTIME, 0);
    }

    public void setValidityEndTimeModifiable(final boolean modifiable) {
        setModifyable(ENDTIME, 0, modifiable);
    }

    /**
     * Optional validity end time in absolute "yyyy-MM-dd HH:mm" or relative "days:hours:minutes" format.
     * @return End time. Never null, but may be empty.
     */
    public String getValidityEndTime() {
        return getValue(ENDTIME, 0);
    }

    public void setValidityEndTime(final String endTime) {
        setValue(ENDTIME, 0, endTime);
    }

    public boolean isCardNumberUsed() {
        return getUse(CARDNUMBER, 0);
    }

    public void setCardNumberUsed(final boolean use) {
        setUse(CARDNUMBER, 0, use);
    }

    public boolean isCardNumberRequired() {
        return isRequired(CARDNUMBER, 0);
    }

    public void setCardNumberRequired(final boolean required) {
        setRequired(CARDNUMBER, 0, required);
    }

    /** @see #getReUseKeyRecoveredCertificate */
    public boolean isKeyRecoverableUsed() {
        return getUse(KEYRECOVERABLE, 0);
    }

    /** @see #setReUseKeyRecoveredCertificate */
    public void setKeyRecoverableUsed(boolean used) {
        setUse(KEYRECOVERABLE, 0, used);
    }

    public boolean isKeyRecoverableDefault() {
        return TRUE.equals(getValue(KEYRECOVERABLE, 0));
    }

    public void setKeyRecoverableDefault(final boolean keyRecoverableDefault) {
        setValue(KEYRECOVERABLE, 0, String.valueOf(keyRecoverableDefault));
    }

    public boolean isKeyRecoverableRequired() {
        return isRequired(KEYRECOVERABLE, 0);
    }

    public void setKeyRecoverableRequired(final boolean required) {
        setRequired(KEYRECOVERABLE, 0, required);
    }

    public boolean isSendNotificationUsed() {
        return getUse(SENDNOTIFICATION, 0);
    }

    public void setSendNotificationUsed(final boolean use) {
        setUse(SENDNOTIFICATION, 0, use);
    }

    public boolean isSendNotificationDefault() {
        return TRUE.equals(getValue(SENDNOTIFICATION, 0));
    }

    public void setSendNotificationDefault(final boolean defaultValue) {
        setValue(SENDNOTIFICATION, 0, String.valueOf(defaultValue));
    }

    public boolean isSendNotificationRequired() {
        return isRequired(SENDNOTIFICATION, 0);
    }
    
    public void setSendNotificationRequired(final boolean required) {
        setRequired(SENDNOTIFICATION, 0, required);
    }

    public List<UserNotification> getUserNotifications() {
    	@SuppressWarnings("unchecked")
        List<UserNotification> l = (List<UserNotification>)data.get(USERNOTIFICATIONS);
    	if (l == null) {
    		l = new ArrayList<>();
    	}
    	return l;
    }

    @SuppressWarnings("unchecked")
    public void addUserNotification(final UserNotification notification) {
    	if (data.get(USERNOTIFICATIONS) == null) {
    		setUserNotifications(new ArrayList<UserNotification>(0));
    	}
    	((List<UserNotification>) data.get(USERNOTIFICATIONS)).add(notification);
    }

    public void setUserNotifications(final List<UserNotification> notifications) {
    	if (notifications == null) {
    		data.put(USERNOTIFICATIONS, new ArrayList<UserNotification>(0));
    	} else {
    		data.put(USERNOTIFICATIONS, notifications);
    	}
    }

    @SuppressWarnings("unchecked")
    public void removeUserNotification(final UserNotification notification) {
    	if (data.get(USERNOTIFICATIONS) != null) {
    		((List<UserNotification>) data.get(USERNOTIFICATIONS)).remove(notification);
    	}
    }

    /** @return true if the key-recovered certificate should be reused. */
    public boolean getReUseKeyRecoveredCertificate(){
    	return getValueDefaultFalse(REUSECERTIFICATE);
    }
    
    public void setReUseKeyRecoveredCertificate(final boolean reuse){
    	data.put(REUSECERTIFICATE, reuse);
    }

    /** @return true if the profile checks should be reversed or not. Default is false. */
    public boolean getReverseFieldChecks(){
    	return getValueDefaultFalse(REVERSEFFIELDCHECKS);
    }
    
    public void setReverseFieldChecks(final boolean reverse){
    	data.put(REVERSEFFIELDCHECKS, reverse);
    }
    
    /** @return true if profile DN should be merged to webservices. Default is false. */
    public boolean getAllowMergeDnWebServices(){
    	return getValueDefaultFalse(ALLOW_MERGEDN_WEBSERVICES);
    }
    
    public void setAllowMergeDnWebServices(final boolean merge){
    	data.put(ALLOW_MERGEDN_WEBSERVICES, merge);
    }

    /** @return true if multi value RDNs should be supported, on a few specific RDNs. Default is false. */
    public boolean getAllowMultiValueRDNs(){
        return getValueDefaultFalse(ALLOW_MULTI_VALUE_RDNS);
    }
    
    public void setAllowMultiValueRDNs(final boolean allow){
        data.put(ALLOW_MULTI_VALUE_RDNS, allow);
    }

    /** @return true if printing of userdata should be done. default is false. */
    public boolean getUsePrinting(){
    	return getValueDefaultFalse(PRINTINGUSE);
    }

    public void setUsePrinting(final boolean use){
    	data.put(PRINTINGUSE, use);
    }
    
    /** @return true if printing of userdata should be done. default is false. */
    public boolean getPrintingDefault(){
    	return getValueDefaultFalse(PRINTINGDEFAULT);
    }
    
    public void setPrintingDefault(final boolean printDefault){
    	data.put(PRINTINGDEFAULT, printDefault);
    }
    
    /** @return true if printing of userdata should be done. default is false. */
    public boolean getPrintingRequired(){
    	return getValueDefaultFalse(PRINTINGREQUIRED);
    }
    
    public void setPrintingRequired(final boolean printRequired){
    	data.put(PRINTINGREQUIRED, printRequired);
    }
    
    /** @return the number of copies that should be printed. Default is 1. */
    public int getPrintedCopies(){
    	if (data.get(PRINTINGCOPIES) == null) {
    		return 1;
    	}
    	return (int) data.get(PRINTINGCOPIES);
    }
    
    public void setPrintedCopies(int copies){
    	data.put(PRINTINGCOPIES, copies);
    }
    
    /** @return the name of the printer that should be used */
    public String getPrinterName(){
    	return getValueDefaultEmpty(PRINTINGPRINTERNAME);
    }
    
    public void setPrinterName(final String printerName){
    	data.put(PRINTINGPRINTERNAME, printerName);
    }
    
    /** @return filename of the uploaded */
    public String getPrinterSVGFileName(){
    	return getValueDefaultEmpty(PRINTINGSVGFILENAME);
    }
    
    public void setPrinterSVGFileName(final String printerSVGFileName){
    	data.put(PRINTINGSVGFILENAME, printerSVGFileName);
    }
    
    /**
     * @return the data of the SVG file, if no content have
     * been uploaded null is returned
     */
    public String getPrinterSVGData(){
        final String value = (String) data.get(PRINTINGSVGDATA);
    	if (StringUtils.isBlank(value)) {
    		return null;
    	}
    	return new String(Base64.decode(value.getBytes(StandardCharsets.US_ASCII)));
    }
    
    public void setPrinterSVGData(final String sVGData){
    	data.put(PRINTINGSVGDATA, new String(Base64.encode(sVGData.getBytes())));
    }
    
    /** @return the boolean value or false if null. Note: Some keys need translating to integer first (e.g. those with use/value/required flags) */
    private boolean getValueDefaultFalse(final Object key) {
    	if (data.get(key) == null) {
    		return false;
    	}
    	return (boolean) data.get(key);
    }

    /** @return the boolean value or false if null. Note: Some keys need translating to integer first (e.g. those with use/value/required flags) */
    private String getValueDefaultEmpty(final Object key) {
    	if (data.get(key) == null) {
    		return "";
    	}
    	return (String) data.get(key);
    }

    public void doesUserFulfillEndEntityProfile(final EndEntityInformation userdata, final boolean clearpwd) throws EndEntityProfileValidationException {
        String subjectdirattr = "";
        final ExtendedInformation ei = userdata.getExtendedInformation();
        if (ei != null) {
            subjectdirattr = ei.getSubjectDirectoryAttributes();
        }
        
        doesUserFulfillEndEntityProfile(userdata.getUsername(), userdata.getPassword(), userdata.getDN(), userdata.getSubjectAltName(), subjectdirattr, userdata.getEmail(), 
    											userdata.getCertificateProfileId(), clearpwd, userdata.getKeyRecoverable(), userdata.getSendNotification(), 
    											userdata.getTokenType(), userdata.getCAId(), userdata.getExtendedInformation());
        //Checking if the cardnumber is required and set
        if (isRequired(CARDNUMBER,0)) {
            if (userdata.getCardNumber()==null || userdata.getCardNumber().isEmpty()) {
               throw new EndEntityProfileValidationException("Cardnumber is not set");
            }
         }
    }
    
    public void doesUserFulfillEndEntityProfile(final String username, final String password, final String dn, final String subjectaltname, final String subjectdirattr,
    		final String email, final int certificateprofileid, final boolean clearpwd, final boolean keyrecoverable, final boolean sendnotification, final int tokentype,
    		final int caid, final ExtendedInformation ei) throws EndEntityProfileValidationException {
    	if (useAutoGeneratedPasswd()) {
        	// Checks related to the use of auto generated passwords
    		if (password != null) {
    			throw new EndEntityProfileValidationException("When using autogenerated password, the provided password must be null.");
    		}
    		if (log.isDebugEnabled()) {
    			log.debug("getAutoGenPwdStrength=" + getAutoGenPwdStrength() + " getMinPwdStrength=" + getMinPwdStrength());
    		}
    		if (getUse(MINPWDSTRENGTH, 0) && (getAutoGenPwdStrength()< getMinPwdStrength())) {
    			throw new EndEntityProfileValidationException("Generated password is not strong enough (" + getAutoGenPwdStrength() + " bits in generated password < " + getMinPwdStrength() + " bits required by end entity profile).");
    		}
    	} else {
        	// Checks related to the use of normal hashed passwords
    		if (!isPasswordModifiable()) {
    			if (!password.equals(getValue(PASSWORD,0))) {
    				throw new EndEntityProfileValidationException("Password didn't match requirement of it's profile.");
    			}
    		} else if (isPasswordRequired()) {
    			if (StringUtils.isBlank(password)) {
    				throw new EndEntityProfileValidationException("Password cannot be empty or null.");
    			}
    		}
    		// Assume a-zA-Z0-9 + 22 other printable chars = 72 different chars. Null password has 0 bits.
    		final int passwordStrengthEstimate = getPasswordStrength(72, (password == null ? 0 : password.trim().length())); 
    		if (log.isDebugEnabled()) {
    			log.debug("passwordStrengthEstimate=" + passwordStrengthEstimate + " getMinPwdStrength=" + getMinPwdStrength());
    		}
    		if (getUse(EndEntityProfile.MINPWDSTRENGTH, 0) && (passwordStrengthEstimate< getMinPwdStrength())) {
    			throw new EndEntityProfileValidationException("Generated password is not strong enough (~" + passwordStrengthEstimate + " bits in specific password < " + getMinPwdStrength() + " bits required by end entity profile).");
    		}
    	}
    	// Checks related to the use of clear text passwords
    	if (!getUse(CLEARTEXTPASSWORD, 0) && clearpwd) {
    		throw new EndEntityProfileValidationException("Clearpassword (used in batch processing) cannot be used.");
    	}
    	if (isRequired(CLEARTEXTPASSWORD, 0)) {
    		if (getValue(CLEARTEXTPASSWORD, 0).equals(TRUE) && !clearpwd) {
    			throw new EndEntityProfileValidationException("Clearpassword (used in batch processing) cannot be false.");
    		}
    		if (getValue(CLEARTEXTPASSWORD, 0).equals(FALSE) && clearpwd) {
    			throw new EndEntityProfileValidationException("Clearpassword (used in batch processing) cannot be true.");
    		}
    	}
    	doesUserFulfillEndEntityProfileWithoutPassword(username, dn, subjectaltname, subjectdirattr, email,
    			certificateprofileid, keyrecoverable, sendnotification, tokentype, caid, ei);
    }

    public void doesUserFulfillEndEntityProfileWithoutPassword(final String username, final String dn, final String subjectaltname, final String subjectdirattr,
    		String email, final int certificateprofileid, final boolean keyrecoverable, final boolean sendnotification, final int tokentype,
    		final int caid, final ExtendedInformation ei) throws EndEntityProfileValidationException {
    	if (log.isTraceEnabled()) {
    		log.trace(">doesUserFulfillEndEntityProfileWithoutPassword()");
    	}
    	// get a DNFieldExtractor used to validate DN fields. Multi-value RDNs are "converted" into non-multi-value RDNs 
    	// just to re-use standard validation mechanisms. 
    	// DNFieldextractor validates (during construction) that only components valid for multi-value use are used.
    	final DNFieldExtractor subjectdnfields = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	if (subjectdnfields.isIllegal()) {
    		throw new EndEntityProfileValidationException("Subject DN is illegal.");
    	}
        if (subjectdnfields.hasMultiValueRDN() && !getAllowMultiValueRDNs()) {
            throw new EndEntityProfileValidationException("Subject DN has multi value RDNs, which is not allowed.");
        }
    	final DNFieldExtractor subjectaltnames = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	if (subjectaltnames.isIllegal()) {
    		throw new EndEntityProfileValidationException("Subject alt names are illegal.");
    	}
    	final DNFieldExtractor subjectdirattrs = new DNFieldExtractor(subjectdirattr, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	if (subjectdirattrs.isIllegal()) {
    		throw new EndEntityProfileValidationException("Subject directory attributes are illegal.");
    	}
    	// Check that no other than supported dn fields exists in the subject dn.
    	if (subjectdnfields.existsOther()) {
    		throw new EndEntityProfileValidationException("Unsupported Subject DN Field found in:" + dn);
    	}
    	if (subjectaltnames.existsOther()) {
    		throw new EndEntityProfileValidationException("Unsupported Subject Alternate Name Field found in:" + subjectaltname );
    	}
    	if (subjectdirattrs.existsOther()) {
    		throw new EndEntityProfileValidationException("Unsupported Subject Directory Attribute Field found in:" + subjectdirattr );
    	}
    	// Make sure that all required fields exist
    	checkIfAllRequiredFieldsExists(subjectdnfields, subjectaltnames, subjectdirattrs, username, email);
    	// Make sure that there are enough fields to cover all required in profile
    	checkIfForIllegalNumberOfFields(subjectdnfields, subjectaltnames, subjectdirattrs);
    	// Check that all fields pass the validators (e.g. regex), if any
    	checkWithValidators(subjectdnfields, subjectaltnames);
    	// Check contents of username
    	checkIfDataFulfillProfile(USERNAME,0,username, "Username",null); 
    	// Check Email address.
    	if (email == null) {
    		email = "";
    	}
    	checkIfDomainFulfillProfile(EMAIL,0,email,"Email");
    	// Make sure that every value has a corresponding field in the entity profile

        checkIfFieldsMatch(subjectdnfields, DNFieldExtractor.TYPE_SUBJECTDN, email, null);
        final String commonName = subjectdnfields.getField(DNFieldExtractor.CN, 0);
        checkIfFieldsMatch(subjectaltnames, DNFieldExtractor.TYPE_SUBJECTALTNAME, email, commonName);
        // Check contents of Subject Directory Attributes fields.
    	final HashMap<Integer,Integer> subjectdirattrnumbers = subjectdirattrs.getNumberOfFields();
    	final List<Integer> dirattrids = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	for (final Integer dirattrid : dirattrids) {
    		final int nof = subjectdirattrnumbers.get(dirattrid);
    		for (int j=0; j<nof; j++) {
    		    final String field = subjectdirattrs.getField(dirattrid, j);
    			checkForIllegalChars(field);
    			switch (dirattrid) {
    			case DNFieldExtractor.COUNTRYOFCITIZENSHIP:
    				checkIfISO3166FulfillProfile(DnComponents.COUNTRYOFCITIZENSHIP, j, field, "COUNTRYOFCITIZENSHIP");
    				break;
    			case DNFieldExtractor.COUNTRYOFRESIDENCE:
    				checkIfISO3166FulfillProfile(DnComponents.COUNTRYOFRESIDENCE, j, field, "COUNTRYOFRESIDENCE");
    				break;
    			case DNFieldExtractor.DATEOFBIRTH:
    				checkIfDateFulfillProfile(DnComponents.DATEOFBIRTH, j, field, "DATEOFBIRTH");
    				break;
    			case DNFieldExtractor.GENDER:
    				checkIfGenderFulfillProfile(DnComponents.GENDER, j, field, "GENDER");
    				break;
    			default:
    				checkIfDataFulfillProfile(DnComponents.dnIdToProfileName(dirattrid), j, field, DnComponents.getErrTextFromDnId(dirattrid), email);
    			}
    		}
    	}
    	// Check for keyrecoverable flag.
    	if (!getUse(KEYRECOVERABLE,0) && keyrecoverable) {
    		throw new EndEntityProfileValidationException("Key Recoverable cannot be used.");
    	}
    	if (isRequired(KEYRECOVERABLE,0) && getValue(KEYRECOVERABLE,0).equals(TRUE)) {
    	    if(tokentype == SecConst.TOKEN_SOFT_BROWSERGEN) {
    	        throw new EndEntityProfileValidationException("Key Recoverable is required, but can't be used for User Generated Tokens.");
    	    }
    		if (getValue(KEYRECOVERABLE,0).equals(TRUE) && !keyrecoverable) {
    			throw new EndEntityProfileValidationException("Key Recoverable is required for this End Entity Profile.");
    		}
    		if (getValue(KEYRECOVERABLE,0).equals(FALSE) && keyrecoverable) {
    			throw new EndEntityProfileValidationException("Key Recoverable cannot be set in current end entity profile.");
    		}
    	}
    	// Check for send notification flag.
    	if (!getUse(SENDNOTIFICATION,0) && sendnotification) {
    		throw new EndEntityProfileValidationException("Email notification cannot be used.");
    	}
    	if (isRequired(SENDNOTIFICATION,0)) {
    		if (getValue(SENDNOTIFICATION,0).equals(TRUE) && !sendnotification) {
    			throw new EndEntityProfileValidationException("Email notification is required.");
    		}
    		if (getValue(SENDNOTIFICATION,0).equals(FALSE) && sendnotification) {
    			throw new EndEntityProfileValidationException("Email notification cannot be set in current end entity profile.");
    		}
    	}
    	// Check if certificate profile is among available certificate profiles.
    	String[] availablecertprofiles;
    	try {
    		availablecertprofiles = getValue(AVAILCERTPROFILES,0).split(SPLITCHAR);
    	} catch (Exception e) {
    		throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    	}
    	if (availablecertprofiles == null) {
    		throw new EndEntityProfileValidationException("Error Available certificate profiles is null.");
    	}
    	final String certificateprofileidString = String.valueOf(certificateprofileid);
    	boolean certprofilefound = false;
    	for (final String currentAvailableCertProfile : availablecertprofiles) {
    		if (certificateprofileidString.equals(currentAvailableCertProfile)) {
    			certprofilefound = true;
    			break;
    		}
    	}
    	if (!certprofilefound) {
    		throw new EndEntityProfileValidationException("Couldn't find certificate profile ("+certificateprofileid+") among available certificate profiles.");
    	}
    	// Check if tokentype is among available token types.
    	String[] availablesofttokentypes;
    	try {
    		availablesofttokentypes = getValue(AVAILKEYSTORE,0).split(SPLITCHAR);
    	} catch (Exception e) {
    		throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    	}
    	if (availablesofttokentypes == null) {
    		throw new EndEntityProfileValidationException("Error available  token types is null.");
    	}
    	final String tokenTypeString = String.valueOf(tokentype);
    	boolean softtokentypefound = false;
    	for (final String currentAvailableSoftTokenType : availablesofttokentypes) {
    		if (tokenTypeString.equals(currentAvailableSoftTokenType)) {
    			softtokentypefound = true;
    			break;
    		}
    	}
    	if (!softtokentypefound) {
    		throw new EndEntityProfileValidationException("Soft token type is not available in End Entity Profile.");
    	}
    	// If soft token check for hardwaretoken issuer id = 0.
    	
    	// Check if ca id is among available ca ids.
    	String[] availablecaids;
    	try {
    		availablecaids = getValue(AVAILCAS,0).split(SPLITCHAR);
    	} catch (Exception e) {
    		throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    	}
    	if (availablecaids == null) {
    		throw new EndEntityProfileValidationException("Error End Entity Profiles Available CAs is null.");
    	}
    	boolean caidfound=false;
    	for (final String currentAvailableCaId : availablecaids) {
    		final int tmp = Integer.parseInt(currentAvailableCaId);
    		if (tmp == caid || tmp == SecConst.ALLCAS) {
    			caidfound = true;
    			break;
    		}
    	}
    	if (!caidfound) {
    		throw new EndEntityProfileValidationException("Couldn't find CA ("+caid+") among End Entity Profiles Available CAs.");
    	}
    	// Check if time constraints are valid
    	String startTime = null;
    	String endTime = null;
    	if ( ei != null ) {
    		startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
    		log.debug("startTime is: "+startTime);
    		endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
    		log.debug("endTime is: "+endTime);
    	}
    	final Date now = new Date();
    	Date startTimeDate = null;
    	if( getUse(STARTTIME, 0) && startTime != null && !startTime.equals("") ) {
    		if ( startTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) { //relative time
    			final String[] startTimeArray = startTime.split(":");
    			if ( Long.parseLong(startTimeArray[0]) < 0 || Long.parseLong(startTimeArray[1]) < 0 || Long.parseLong(startTimeArray[2]) < 0 ) {
    				throw new EndEntityProfileValidationException("Cannot use negtive relative time.");
    			}
    			final long relative = (Long.parseLong(startTimeArray[0])*24*60 + Long.parseLong(startTimeArray[1])*60 +
    					Long.parseLong(startTimeArray[2])) * 60 * 1000;
    			startTimeDate = new Date(now.getTime() + relative);
    		} else {
    			try {
    				startTimeDate = ValidityDate.parseAsUTC(startTime);
    			} catch (ParseException e) {
    			}
    		}
    		if (startTimeDate == null) {
    			// If we could not parse the date string, something was awfully wrong
    			throw new EndEntityProfileValidationException("Invalid start time: "+startTime);    		  
    		}
    	}
    	Date endTimeDate = null;
    	if( getUse(ENDTIME, 0) && endTime != null && !endTime.equals("") ) {
    		if ( endTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) { //relative time
    			final String[] endTimeArray = endTime.split(":");
    			if ( Long.parseLong(endTimeArray[0]) < 0 || Long.parseLong(endTimeArray[1]) < 0 || Long.parseLong(endTimeArray[2]) < 0 ) {
    				throw new EndEntityProfileValidationException("Cannot use negtive relative time.");
    			}
    			final long relative = (Long.parseLong(endTimeArray[0])*24*60 + Long.parseLong(endTimeArray[1])*60 +
    					Long.parseLong(endTimeArray[2])) * 60 * 1000;
    			// If we haven't set a startTime, use "now"
    			final Date start = (startTimeDate == null) ? new Date(): startTimeDate;
    			endTimeDate = new Date(start.getTime() + relative);
    		} else {
    			try {
    			    endTimeDate = ValidityDate.parseAsUTC(endTime);
    			} catch (ParseException e) {
    			}
    		}
    		if (endTimeDate == null) {
    			// If we could not parse the date string, something was awfulyl wrong
    			throw new EndEntityProfileValidationException("Invalid end time: "+endTime);    		  
    		}
    	}
    	if ( (startTimeDate != null) && (endTimeDate != null) ) {
    		if ( getUse(STARTTIME, 0) && getUse(ENDTIME, 0) && !startTimeDate.before(endTimeDate) ) {
    			throw new EndEntityProfileValidationException("Dates must be in right order. "+startTime+" "+endTime+" "+
    					ValidityDate.formatAsUTC(startTimeDate)+" "+ValidityDate.formatAsUTC(endTimeDate));
    		}    	  
    	}
    	// Check number of allowed requests
    	String allowedRequests = null;
    	if ( ei != null ) {
    		allowedRequests = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
    	}
    	if ( (allowedRequests != null) && !getUse(ALLOWEDREQUESTS, 0) ) {
    		throw new EndEntityProfileValidationException("Allowed requests used, but not permitted by profile.");
    	}
    	// Check initial issuance revocation reason
    	String issuanceRevReason = null;
    	if ( ei != null ) {
    		issuanceRevReason = ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
    	}
    	if ( (issuanceRevReason != null) && !getUse(ISSUANCEREVOCATIONREASON, 0) ) {
    		throw new EndEntityProfileValidationException("Issuance revocation reason used, but not permitted by profile.");
    	}
    	if ( getUse(ISSUANCEREVOCATIONREASON, 0) && !isModifyable(ISSUANCEREVOCATIONREASON, 0) ) {
    		final String value = getValue(ISSUANCEREVOCATIONREASON, 0);
    		if (!StringUtils.equals(issuanceRevReason, value)) {
    			throw new EndEntityProfileValidationException("Issuance revocation reason '"+issuanceRevReason+"' does not match required value '"+value+"'.");
    		}
    	}
    	// Check maximum number of failed logins
    	if ( getUse(MAXFAILEDLOGINS, 0) && !isModifyable(MAXFAILEDLOGINS,0)) {
    		// If we MUST have MAXFAILEDLOGINS, ei can not be null
    		if ( (ei == null) || !getValue(MAXFAILEDLOGINS,0).equals(Integer.toString(ei.getMaxLoginAttempts())) ) {
    			throw new EndEntityProfileValidationException("Max failed logins is not modifyable.");
    		}
    	}
    	// Check if PSD2 QC Statement is allowed when requested
    	if (ei != null && !isPsd2QcStatementUsed() && (ei.getQCEtsiPSD2NCAName() != null || ei.getQCEtsiPSD2NCAId() != null || ei.getQCEtsiPSD2RolesOfPSP() != null)) {
    	    throw new EndEntityProfileValidationException("ETSI PSD2 QC Statements was requested but not permitted by end entity profile.");
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<doesUserFulfillEndEntityProfileWithoutPassword()");
    	}
    }

    /**
     * This function tries to match each field in the profile to a corresponding field in the DN/AN/AD-fields.
     * Can not be used for DNFieldExtractor.TYPE_SUBJECTDIRATTR yet.
     *   
     * @param fields
     * @param type One of DNFieldExtractor.TYPE_SUBJECTDN, DNFieldExtractor.TYPE_SUBJECTALTNAME
     * @param email The end entity's email address
     * @throws EndEntityProfileValidationException
     */
    private void checkIfFieldsMatch(final DNFieldExtractor fields, final int type, final String email, final String commonName) throws EndEntityProfileValidationException {
    	final int REQUIRED_FIELD		= 2;
    	final int NONMODIFYABLE_FIELD	= 1;
    	final int MATCHED_FIELD			= -1;
    	final List<Integer> dnids = DNFieldExtractor.getUseFields(type);
    	// For each type of field
    	for ( int i=0; i<dnids.size(); i++ ) {
    		final int dnid = dnids.get(i);
    		final int profileID = DnComponents.dnIdToProfileId(dnid);
    		final int dnFieldExtractorID = DnComponents.profileIdToDnId(profileID);
    		final int nof = fields.getNumberOfFields(dnFieldExtractorID);
    		final int numberOfProfileFields = getNumberOfField(profileID);
    		if ( nof == 0 && numberOfProfileFields == 0 ) {
    			continue;	// Nothing to see here..
    		}
    		// Create array with all entries of that type
    		final String[] subjectsToProcess = new String[nof];
    		for ( int j=0; j<nof; j++ ) {
    			String fieldValue = fields.getField(dnFieldExtractorID, j);
    			// Only keep domain for comparison of RFC822NAME, DNEMAILADDRESS and UPN fields
    			if ( DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.DNEMAILADDRESS.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.UPN.equals(DnComponents.dnIdToProfileName(dnid)) ) {
        			//Don't split RFC822NAME addresses. 
        			if(!DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid))) {
                        if (!StringUtils.contains(fieldValue, '@')) {
                            throw new EndEntityProfileValidationException("Field value DNEMAIL and UPN must contain an @ character: "+fieldValue);
                       }
        			    fieldValue = fieldValue.split("@")[1];
        			}
    			} else {
        			// Check that postalAddress has #der_encoding_in_hex format, i.e. a full der sequence in hex format
        			if ( DnComponents.POSTALADDRESS.equals(DnComponents.dnIdToProfileName(dnid))) {
        				if (!StringUtils.startsWith(fieldValue, "#30")) {
            				throw new EndEntityProfileValidationException(DnComponents.dnIdToProfileName(dnid) + " ("+fieldValue+") does not seem to be in #der_encoding_in_hex format. See \"End_Entity_Profiles.html\" for more information about the postalAddress (2.5.4.16) field.");        					
        				}
        			}    				
    			}
    			subjectsToProcess[j] = fieldValue;
    		}
    		//	Create array with profile values 3 = required and non-mod, 2 = required, 1 = non-modifiable, 0 = neither
    		final int[] profileCrossOffList = new int[numberOfProfileFields];
    		for ( int j=0; j< getNumberOfField(profileID); j++ ) {
    			profileCrossOffList[j] += ( isModifyable(profileID, j) ? 0 : NONMODIFYABLE_FIELD ) + ( isRequired(profileID, j) ? REQUIRED_FIELD : 0 ); 
    		}
    		// Start by matching email strings
			if ( DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.DNEMAILADDRESS.equals(DnComponents.dnIdToProfileName(dnid)) ) {
	    		for ( int k=3; k>=0; k--) {
	    			//	For every value in profile
	    			for ( int l=0; l<profileCrossOffList.length; l++ ) {
	    				if ( profileCrossOffList[l] == k ) {
	    					//	Match with every value in field-array
	    					for ( int m=0; m<subjectsToProcess.length; m++ ) {
	    						if ( subjectsToProcess[m] != null && profileCrossOffList[l] != MATCHED_FIELD ) {				
	    						    if (getUse(profileID, l) || !DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid))) {
	    						         /*
	                                     * IF the component is E-Mail (not RFC822NAME) 
	                                     * OR if it is RFC822NAME AND E-Mail field from DN should be used 
	                                     */
	    								if (fields.getField(dnFieldExtractorID, m).equals(email) ){
	    									subjectsToProcess[m] = null;
	    									profileCrossOffList[l] = MATCHED_FIELD;
	    								}
	    							}
	    						}
	    					}
	    				}
	    			}
	    		}
			}
            if (DnComponents.DNSNAME.equals(DnComponents.dnIdToProfileName(dnid))) {
                verifyDnsNameFieldMatchesCnValue(fields, commonName, MATCHED_FIELD, profileID, dnFieldExtractorID, subjectsToProcess, profileCrossOffList);
            }
            // For every field of this type in profile (start with required and non-modifiable, 2 + 1)
            for (int k = 3; k >= 0; k--) {
                // For every value in profile
                for (int l = 0; l < profileCrossOffList.length; l++) {
                    if (profileCrossOffList[l] == k) {
                        // Match with every value in field-array
                        for (int m = 0; m < subjectsToProcess.length; m++) {
                            if (subjectsToProcess[m] != null && profileCrossOffList[l] != MATCHED_FIELD) {
                                // Match actual value if required + non-modifiable or non-modifiable
                                if ((k == (REQUIRED_FIELD + NONMODIFYABLE_FIELD) || k == (NONMODIFYABLE_FIELD))) {
                                    // Try to match with all possible values
                                    String[] fixedValues = getValue(profileID, l).split(SPLITCHAR);
                                    for (int n = 0; n < fixedValues.length; n++) {
                                        if (subjectsToProcess[m] != null && subjectsToProcess[m].equals(fixedValues[n])) {
                                            // Remove matched pair
                                            subjectsToProcess[m] = null;
                                            profileCrossOffList[l] = MATCHED_FIELD;
                                        }
                                    }

                                    // Otherwise just match present fields
                                } else {
                                    // Remove matched pair
                                    subjectsToProcess[m] = null;
                                    profileCrossOffList[l] = MATCHED_FIELD;
                                }
                            }
                        }
                    }
                }
            }
    		// If not all fields in profile were found
    		for ( int j=0; j< nof; j++ ) {
    			if ( subjectsToProcess[j] != null ) {
    				throw new EndEntityProfileValidationException("End entity profile does not contain matching field for " +
    						DnComponents.dnIdToProfileName(dnid) + " with value \"" + subjectsToProcess[j] + "\".");
    			}
    		}
    		// If not all required fields in profile were found in subject 
    		for ( int j=0; j< getNumberOfField(profileID); j++ ) {
    			if ( profileCrossOffList[j] >= REQUIRED_FIELD ) {
    				throw new EndEntityProfileValidationException("Data does not contain required " + DnComponents.dnIdToProfileName(dnid) + " field.");
    			}
    		}
    	}
    } // checkIfFieldsMatch

    private void verifyDnsNameFieldMatchesCnValue(final DNFieldExtractor fields, String commonName, final int matchedField, final int profileID,
                                                  final int dnFieldExtractorID, String[] subjectsToProcess, int[] profileCrossOffList) {
        //0,1,2,3 are combinations of modifiable and required
        for (int k = 3; k >= 0; k--) {
            //	For every value in profile
            for (int l = 0; l < profileCrossOffList.length; l++) {
                if (profileCrossOffList[l] == k) {
                    //	Match with every value in field-array
                    for (int m = 0; m < subjectsToProcess.length; m++) {
                        if (subjectsToProcess[m] != null && profileCrossOffList[l] != matchedField) {
                            if (getCopy(profileID, l)) {
                                 /*
                                 * IF the component is DNSNAME and getCopy is true, value from CN should be used
                                 */
                                if (fields.getField(dnFieldExtractorID, m).equals(commonName)) {
                                    subjectsToProcess[m] = null;
                                    profileCrossOffList[l] = matchedField;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public void doesPasswordFulfillEndEntityProfile(String password, boolean clearpwd) throws EndEntityProfileValidationException {
		boolean fulfillsprofile = true;
		if (useAutoGeneratedPasswd()) {
			if (password !=null) {
				throw new EndEntityProfileValidationException("Autogenerated password must have password==null");
			}
		} else {           		            
			if (!isPasswordModifiable()) {
				if(!password.equals(getPredefinedPassword())) {
					fulfillsprofile = false;
				}
			} else {
				if (isPasswordRequired()) {
					if((!clearpwd && password == null) || (password != null && password.trim().equals(""))) {			
						fulfillsprofile = false;
					}
				}
			}
		}
		if (clearpwd && isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) && getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.FALSE)){		 	
			fulfillsprofile = false;
		}
		if (!fulfillsprofile) {
			throw new EndEntityProfileValidationException("Password doesn't fulfill profile.");
		}
	}

	@Override
    public Object clone() throws CloneNotSupportedException {
    	final EndEntityProfile clone = new EndEntityProfile(0);
    	// We need to make a deep copy of the hashmap here
    	clone.data = new LinkedHashMap<>(data.size());
    	for (final Entry<Object,Object> entry : data.entrySet()) {
    		Object value = entry.getValue();
    		if (value instanceof ArrayList<?>) {
    			// We need to make a clone of this object, but the stored Integers can still be referenced
    			value = ((ArrayList<?>)value).clone();
    		}
    		clone.data.put(entry.getKey(), value);
    	}
    	return clone;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
	@Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */
	@Override
    public void upgrade() {
        log.trace(">upgrade");        
    	if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
			String msg = intres.getLocalizedMessage("ra.eeprofileupgrade", getVersion());
            log.info(msg);
            // New version of the class, upgrade
            if (getVersion() < 1) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberarray = (ArrayList<Integer>) data.get(NUMBERARRAY);
                while (numberarray.size() < 37) {
                   numberarray.add(0);
                }
                data.put(NUMBERARRAY,numberarray);
            }
            if (getVersion() < 2) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberarray = (ArrayList<Integer>) data.get(NUMBERARRAY);
                while (numberarray.size() < 39) {
                   numberarray.add(0);
                }
                data.put(NUMBERARRAY,numberarray);
                addField(AVAILCAS);
                addField(DEFAULTCA);
                setRequired(AVAILCAS,0,true);
                setRequired(DEFAULTCA,0,true);
            }
            if (getVersion() < 3) {
            	// These fields have been removed in version 8, no need for this upgrade
                //setNotificationSubject("");
                //setNotificationSender("");
                //setNotificationMessage("");
            }
            if (getVersion() < 4) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberoffields = (ArrayList<Integer>) data.get(NUMBERARRAY);                
                for (int i =numberoffields.size(); i < dataConstants.size(); i++) {
                  numberoffields.add(0);
                }               
                data.put(NUMBERARRAY,numberoffields);                
            }
            // Support for DirectoryName altname field in profile version 5
            if (getVersion() < 5) {
                addField(DnComponents.DIRECTORYNAME);
                setValue(DnComponents.DIRECTORYNAME,0,"");
                setRequired(DnComponents.DIRECTORYNAME,0,false);
                setUse(DnComponents.DIRECTORYNAME,0,true);
                setModifyable(DnComponents.DIRECTORYNAME,0,true);            	
            }
            // Support for Subject Directory Attributes field in profile version 6
            if (getVersion() < 6) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberoffields = (ArrayList<Integer>) data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                  numberoffields.add(0);
                }               
                data.put(NUMBERARRAY,numberoffields);
                data.put(SUBJECTDIRATTRFIELDORDER,new ArrayList<Integer>());
                
                for(int i=getParameterNumber(DnComponents.DATEOFBIRTH); i <= getParameterNumber(DnComponents.COUNTRYOFRESIDENCE); i++){
                	addField(getParameter(i));
                	setValue(getParameter(i),0,"");
                	setRequired(getParameter(i),0,false);
                	setUse(getParameter(i),0,false);
                	setModifyable(getParameter(i),0,true);
                }  
            }
            // Support for Start Time and End Time field in profile version 7
            if (getVersion() < 7) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberoffields = (ArrayList<Integer>) data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                	numberoffields.add(0);
                }               
                data.put(NUMBERARRAY,numberoffields);
                addField(STARTTIME);
                setValue(STARTTIME, 0, "");
                setRequired(STARTTIME, 0, false);
                setUse(STARTTIME, 0, false);
                setModifyable(STARTTIME, 0, true);            	
                addField(ENDTIME);
                setValue(ENDTIME, 0, "");
                setRequired(ENDTIME, 0, false);
                setUse(ENDTIME, 0, false);
                setModifyable(ENDTIME, 0, true);            	
            }
            // Notifications is now a more general mechanism in version 8
            if (getVersion() < 8) {
            	log.debug("Upgrading User Notifications");
            	if (data.get(UserNotification.NOTIFICATIONSENDER) != null) {
            		UserNotification not = new UserNotification();
            		not.setNotificationSender((String)data.get(UserNotification.NOTIFICATIONSENDER));
            		if (data.get(UserNotification.NOTIFICATIONSUBJECT) != null) {
                		not.setNotificationSubject((String)data.get(UserNotification.NOTIFICATIONSUBJECT));            			
            		}
            		if (data.get(UserNotification.NOTIFICATIONMESSAGE) != null) {
                		not.setNotificationMessage((String)data.get(UserNotification.NOTIFICATIONMESSAGE));            			
            		}
            		// Add the statuschanges we used to send notifications about
            		String events = UserNotification.EVENTS_EDITUSER;
            		not.setNotificationEvents(events);
            		// The old recipients where always the user
            		not.setNotificationRecipient(UserNotification.RCPT_USER);
            		addUserNotification(not);
            	}
            }
            // Support for allowed requests in profile version 9
            if (getVersion() < 9) {
                @SuppressWarnings("unchecked")
                ArrayList<Integer> numberoffields = (ArrayList<Integer>) data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                	numberoffields.add(0);
                }               
                data.put(NUMBERARRAY,numberoffields);
                addField(ALLOWEDREQUESTS);
                setValue(ALLOWEDREQUESTS, 0, "");
                setRequired(ALLOWEDREQUESTS, 0, false);
                setUse(ALLOWEDREQUESTS, 0, false);
                setModifyable(ALLOWEDREQUESTS, 0, true);            	
            }
            // Support for merging DN from WS-API with default values in profile, in profile version 10
            if (getVersion() < 10) {
                setAllowMergeDnWebServices(false);
            }
            // Support for issuance revocation status in profile version 11
            if (getVersion() < 11) {
                setRequired(ISSUANCEREVOCATIONREASON, 0, false);
                setUse(ISSUANCEREVOCATIONREASON, 0, false);
                setModifyable(ISSUANCEREVOCATIONREASON, 0, true);
                setValue(ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);
                setRequired(CARDNUMBER, 0, false);
                setUse(CARDNUMBER, 0, false);
                setModifyable(CARDNUMBER, 0, true);            	
            }
            // Support for maximum number of failed login attempts in profile version 12
            if (getVersion() < 12) {
            	setRequired(MAXFAILEDLOGINS, 0, false);
            	setUse(MAXFAILEDLOGINS, 0, false);
            	setModifyable(MAXFAILEDLOGINS, 0, true);
            	setValue(MAXFAILEDLOGINS, 0, Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS));
            }
            /* In EJBCA 4.0.0 we changed the date format to ISO 8601.
             * In the Admin GUI the example was:
             *     DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, ejbcawebbean.getLocale())
             * but the only absolute format that could have worked is the same enforced by the 
             * doesUserFulfillEndEntityProfile check and this is what need to upgrade from:
             * 	   DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US)
             */
        	if (getVersion() < 13) {
        		final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
        		final FastDateFormat newDateFormat = FastDateFormat.getInstance("yyyy-MM-dd HH:mm");
        		try {
        			final String oldStartTime = getValue(STARTTIME, 0);
        			if (!isEmptyOrRelative(oldStartTime)) {
        				// We use an absolute time format, so we need to upgrade
            			final String newStartTime = newDateFormat.format(oldDateFormat.parse(oldStartTime));
    					setValue(STARTTIME, 0, newStartTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + STARTTIME + " from \"" + oldStartTime + "\" to \"" + newStartTime + "\" in EndEntityProfile.");
    					}
        			}
				} catch (ParseException e) {
					log.error("Unable to upgrade " + STARTTIME + " in EndEntityProfile! Manual interaction is required (edit and verify).", e);
				}
        		try {
        			final String oldEndTime = getValue(ENDTIME, 0);
        			if (!isEmptyOrRelative(oldEndTime)) {
        				// We use an absolute time format, so we need to upgrade
            			final String newEndTime = newDateFormat.format(oldDateFormat.parse(oldEndTime));
    					setValue(ENDTIME, 0, newEndTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + ENDTIME + " from \"" + oldEndTime + "\" to \"" + newEndTime + "\" in EndEntityProfile.");
    					}
        			}
				} catch (ParseException e) {
					log.error("Unable to upgrade " + ENDTIME + " in EndEntityProfile! Manual interaction is required (edit and verify).", e);
				}
        	}
        	/*
        	 * In version 13 we converted some dates to the "yyyy-MM-dd HH:mm" format using default Locale.
        	 * These needs to be converted to the same format but should be stored in UTC, so we always know what the times are.
        	 */
        	if (getVersion() < 14) {
        		final String[] timePatterns = {"yyyy-MM-dd HH:mm"};
    			final String oldStartTime = getValue(STARTTIME, 0);
    			if (!isEmptyOrRelative(oldStartTime)) {
            		try {
            			final String newStartTime = ValidityDate.formatAsUTC(DateUtils.parseDateStrictly(oldStartTime, timePatterns));
    					setValue(STARTTIME, 0, newStartTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + STARTTIME + " from \"" + oldStartTime + "\" to \"" + newStartTime + "\" in EndEntityProfile.");
    					}
					} catch (ParseException e) {
						log.error("Unable to upgrade " + STARTTIME + " to UTC in EndEntityProfile! Manual interaction is required (edit and verify).", e);
					}
    			}
    			final String oldEndTime = getValue(ENDTIME, 0);
    			if (!isEmptyOrRelative(oldEndTime)) {
    				// We use an absolute time format, so we need to upgrade
					try {
						final String newEndTime = ValidityDate.formatAsUTC(DateUtils.parseDateStrictly(oldEndTime, timePatterns));
						setValue(ENDTIME, 0, newEndTime);
						if (log.isDebugEnabled()) {
							log.debug("Upgraded " + ENDTIME + " from \"" + oldEndTime + "\" to \"" + newEndTime + "\" in EndEntityProfile.");
						}
					} catch (ParseException e) {
						log.error("Unable to upgrade " + ENDTIME + " to UTC in EndEntityProfile! Manual interaction is required (edit and verify).", e);
					}
    			}
        	}
        	// In version 15 (EJBCA 7.0) we included ability for multi-value RDNs
            if (getVersion() < 15) {
                setAllowMultiValueRDNs(false);
            }

        	// Finally, update the version stored in the map to the current version
            data.put(VERSION, LATEST_VERSION);
        }
        log.trace("<upgrade");
    }
    
    /** @return true if argument is null, empty or in the relative time format. */
    private boolean isEmptyOrRelative(final String time) {
    	return (time == null || time.length()==0 || time.matches("^\\d+:\\d?\\d:\\d?\\d$"));
    }

    public static boolean isFieldImplemented(final int field) {
    	final String f = getParameter(field);
    	if (f == null) {
    	    if (log.isTraceEnabled()) {
                log.trace("isFieldImplemented got call for non-implemented field: "+field);
    	    }
    		return false;
    	}
    	return isFieldImplemented(f);
    }

    public static boolean isFieldImplemented(final String field) {
    	boolean ret = true;
        if (field.equals(DnComponents.OTHERNAME) 
        		|| field.equals(DnComponents.X400ADDRESS) 
        		|| field.equals(DnComponents.EDIPARTYNAME)) {
            if (log.isDebugEnabled()) {
                log.debug("isFieldImplemented got call for non-implemented/ignored subjectAltName field (custom extension is required): "+field);
            }
        	ret = false;
        }
        return ret;
    }

	public static boolean isFieldOfType(final int fieldNumber, final String fieldString) {
		boolean ret = false;
		final int number = getParameterNumber(fieldString);
		if (fieldNumber == number) {
			ret = true;
		}
		return ret;
	}

    //
    // Private Methods
    //

    /**
     * Verify that the field contains an address and that data of non-modifyable domain-fields is available in profile 
     * Used for email, upn and rfc822 fields
     */
    private void checkIfDomainFulfillProfile(final String field, final int number, final String nameAndDomain, final String text) throws EndEntityProfileValidationException {
    	if (!nameAndDomain.trim().equals("") && nameAndDomain.indexOf('@') == -1) {
    		throw new EndEntityProfileValidationException("Invalid " + text + "(" + nameAndDomain + "). There must be a '@' character in the field.");
    	}
    	final String domain = nameAndDomain.substring(nameAndDomain.indexOf('@') + 1);
    	// All fields except RFC822NAME has to be empty if not used flag is set.
    	if ( !DnComponents.RFC822NAME.equals(field) && !getUse(field,number) && !nameAndDomain.trim().equals("") ) {
    		throw new EndEntityProfileValidationException(text + " cannot be used in end entity profile.");
    	}
    	if (!isModifyable(field,number) && !nameAndDomain.equals("")) {
    		String[] values;
    		try {
    			values = getValue(field, number).split(SPLITCHAR);
    		} catch (Exception e) {
    			throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    		}
    		boolean exists = false;
    		for (final String value : values) {
    			if(domain.equals(value.trim())) {
    				exists = true;
    				break;
    			}
    		}
    		if (!exists) {
    			throw new EndEntityProfileValidationException("Field " + text + " data didn't match requirement of end entity profile.");
    		}
    	}
    }
    
    private void checkForIllegalChars(final String str) throws EndEntityProfileValidationException {
        Set<String> invalidCharacters = StringTools.hasSqlStripChars(str);
    	if (!invalidCharacters.isEmpty()) {
    	    StringBuilder sb = new StringBuilder("");
    	    for(String error : invalidCharacters) {
    	        sb.append(", " + error) ;
    	    }	    
    		throw new EndEntityProfileValidationException("Invalid " + str + ". Contains illegal characters: " + sb.substring(2));    		
    	}    	
    }

    /** Used for iso 3166 country codes. */
    private void checkIfISO3166FulfillProfile(final String field, final int number, final String country, final String text) throws EndEntityProfileValidationException {
    	final String countryTrim = country.trim();
    	final int countryTrimLength = countryTrim.length();
    	if (countryTrimLength != 0 && countryTrimLength != 2) {
    		throw new EndEntityProfileValidationException("Invalid " + text + ". Must be of length two.");
    	}
    	if (!getUse(field,number) && countryTrimLength != 0) {
    		throw new EndEntityProfileValidationException(text + " cannot be used in end entity profile.");
    	}
    	if (!isModifyable(field,number) && countryTrimLength != 0) {
    		String[] values;
    		try {
    			values = getValue(field, number).split(SPLITCHAR);
    		} catch (Exception e) {
    			throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    		}
    		boolean exists = false;
    		for (final String value : values) {
    			if (country.equals(value.trim())) {
    				exists = true;
    				break;
    			}
    		}
    		if (!exists) {
    			throw new EndEntityProfileValidationException("Field " + text + " data didn't match requirement of end entity profile.");
    		}
    	}
    }
    
    /** Used to check if it is an M or an F */
    private void checkIfGenderFulfillProfile(final String field, final int number, final String gender, final String text) throws EndEntityProfileValidationException {
    	final boolean isGenerEmpty = gender.trim().isEmpty();
    	if (!isGenerEmpty && !(gender.equalsIgnoreCase("m") || gender.equalsIgnoreCase("f"))) {
    		throw new EndEntityProfileValidationException("Invalid " + text + ". Must be M or F.");
    	}
    	if (!getUse(field,number) && !isGenerEmpty) {
    		throw new EndEntityProfileValidationException(text + " cannot be used in end entity profile.");
    	}
    	if (!isModifyable(field,number) && !isGenerEmpty) {
    		String[] values;
    		try {
    			values = getValue(field, number).split(SPLITCHAR);
    		} catch(Exception e) {
    			throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    		}
    		boolean exists = false;
    		for (final String value: values) {
    			if (gender.equals(value.trim())) {
    				exists = true;
    				break;
    			}
    		}
    		if (!exists) {
    			throw new EndEntityProfileValidationException("Field " + text + " data didn't match requirement of end entity profile.");
    		}
    	}
    }

    /** Used for date strings, should be YYYYMMDD */
    private void checkIfDateFulfillProfile(final String field, final int number, final String date, final String text) throws EndEntityProfileValidationException {
    	final String dateTrim = date.trim();
    	final boolean isDateEmpty = dateTrim.isEmpty();
    	if (!isDateEmpty && dateTrim.length() != 8) {
    		throw new EndEntityProfileValidationException("Invalid " + text + ". Must be of length eight.");
    	}
    	if (!isDateEmpty && !StringUtils.isNumeric(dateTrim)) {
    		throw new EndEntityProfileValidationException("Invalid " + text + ". Must be only numbers.");
    	}
    	if (!getUse(field,number) && !isDateEmpty) {
    		throw new EndEntityProfileValidationException(text + " cannot be used in end entity profile.");
    	}
    	if (!isModifyable(field,number) && !isDateEmpty) {
    		String[] values;
    		try {
    			values = getValue(field, number).split(SPLITCHAR);
    		} catch (Exception e) {
    			throw new EndEntityProfileValidationException("Error parsing end entity profile.");
    		}
    		boolean exists = false;
    		for (final String value : values) {
    			if (date.equals(value.trim())) {
    				exists = true;
    				break;
    			}
    		}
    		if (!exists) {
    			throw new EndEntityProfileValidationException("Field " + text + " data didn't match requirement of end entity profile.");
    		}
    	}
    }

    /**
     * Verifies that non-modifiable data is available in profile.
     * @throws EndEntityProfileValidationException
     */
    private void checkIfDataFulfillProfile(final String field, final int number, final String value, final String text, final String email) throws EndEntityProfileValidationException {
        //If USERNAME should be autogenerated skip this check
        if (field.equals(USERNAME) && !isModifyable(USERNAME, 0)){
            return;
        }
    	if (value == null && !field.equals(EMAIL)) {
    		throw new EndEntityProfileValidationException("Field " +  text + " cannot be null.");
    	}
    	if (value !=null) {
    		if (!getUse(field,number) && !value.trim().isEmpty()) {
    			throw new EndEntityProfileValidationException(text + " cannot be used in end entity profile.");
    		}
    	}
    	if (field.equals(DnComponents.DNEMAILADDRESS)) {
    		if (isRequired(field,number)) {
    			if (!value.trim().equals(email.trim())) {
    				throw new EndEntityProfileValidationException("Field " + text + " data didn't match Email field.");
    			}
    		}
    	} else if (field.equals(DnComponents.RFC822NAME) && isRequired(field,number) && getUse(field,number)) {
    		if (!value.trim().equals(email.trim())) {
    			throw new EndEntityProfileValidationException("Field " + text + " data didn't match Email field.");
    		}
    	} else {
    		if (!isModifyable(field,number)) {
    			final String[] allowedValues;
    			try {
    				allowedValues = getValue(field, number).split(SPLITCHAR);
    			} catch (RuntimeException e) {
    				throw new EndEntityProfileValidationException("Error parsing end entity profile.", e);
    			}
    			boolean exists = false;
    			for (final String allowedValue : allowedValues) {
    				if (value.equals(allowedValue.trim())) {
    					exists = true;
    				}
    			}
    			if (!exists) {
    				throw new EndEntityProfileValidationException("Field " + text + " data didn't match requirement of end entity profile.");
    			}
    		}
    	}
    }

    private void checkIfAllRequiredFieldsExists(final DNFieldExtractor subjectdnfields, final DNFieldExtractor subjectaltnames, final DNFieldExtractor subjectdirattrs, final String username, final String email)
    throws EndEntityProfileValidationException {
    	// Check if Username exists (if not modifiable skip the check)
    	if (isRequired(USERNAME,0) && isModifyable(USERNAME, 0)) {
    		if (username == null || username.trim().isEmpty() ) {
    			throw new EndEntityProfileValidationException("Username cannot be empty or null.");
    		}
    	}
    	// Check if required Email fields exists.
    	if (isRequired(EMAIL,0)) {
    		if (StringUtils.isBlank(email)) {
    			throw new EndEntityProfileValidationException("Email address cannot be empty or null.");
    		}
    	}
    	// Check if all required subjectdn fields exists.
    	final List<String> dnfields = DnComponents.getDnProfileFields();
    	final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
    	for (int i = 0; i<dnfields.size(); i++) {
    		final String currentDnField = dnfields.get(i);
    		if (getReverseFieldChecks()) {
    			final int nof = subjectdnfields.getNumberOfFields(dnFieldExtractorIds.get(i));
    			final int numRequiredFields = getNumberOfRequiredFields(currentDnField);
    			if (nof < numRequiredFields) {
    				throw new EndEntityProfileValidationException("Subject DN field '" + currentDnField + "' must exist.");
    			}
    		} else {
    			final int size = getNumberOfField(currentDnField);
    			for (int j = 0; j<size; j++) {
    				if (isRequired(currentDnField,j)) {
    					if (StringUtils.isBlank(subjectdnfields.getField(dnFieldExtractorIds.get(i), j))) {
    						throw new EndEntityProfileValidationException("Subject DN field '" + currentDnField + "' must exist.");
    					}
    				}
    			}
    		}
    	}
    	// Check if all required subject alternate name fields exists.
    	final List<String> altnamefields = DnComponents.getAltNameFields();
    	final List<Integer> altNameFieldExtractorIds = DnComponents.getAltNameDnIds();
    	for (int i=0; i<altnamefields.size(); i++) {
    		final String currentAnField = altnamefields.get(i);
    		if (getReverseFieldChecks()) {
    			final int nof = subjectaltnames.getNumberOfFields(altNameFieldExtractorIds.get(i));
    			final int numRequiredFields = getNumberOfRequiredFields(currentAnField);
    			if (nof < numRequiredFields) {
    				throw new EndEntityProfileValidationException("Subject Alternative Name field '" + currentAnField + "' must exist.");
    			}
    		} else {
    			// Only verify fields that are actually used
    			// size = getNumberOfField(altnamefields[i]);
    			final int size = subjectaltnames.getNumberOfFields(altNameFieldExtractorIds.get(i));
    			for (int j = 0; j < size; j++) {
    				if (isRequired(currentAnField,j)) {
    					if (StringUtils.isBlank(subjectaltnames.getField(altNameFieldExtractorIds.get(i), j))) {
    						throw new EndEntityProfileValidationException("Subject Alterntive Name field '" + currentAnField + "' must exist.");
    					}
    				}
    			}
    		}
    	}
    	// Check if all required subject directory attribute fields exists.
    	final List<String> dirattrfields = DnComponents.getDirAttrFields();
    	final List<Integer> dirAttrFieldExtractorIds = DnComponents.getDirAttrDnIds();
    	for (int i = 0; i < dirattrfields.size(); i++) {        	
    		final String currentDaField = dirattrfields.get(i);
    		final int size = getNumberOfField(currentDaField);
    		for (int j = 0; j < size; j++) {
    			if (isRequired(currentDaField,j)) {
    				if (StringUtils.isBlank(subjectdirattrs.getField(dirAttrFieldExtractorIds.get(i), j))) {
    					throw new EndEntityProfileValidationException("Subject Directory Attribute field '" + currentDaField + "' must exist.");
    				}
    			}
    		}
    	}
    }

    /**
     * Method calculating the number of required fields of on kind that is configured for this profile.
     * @param field one of the field constants
     * @return The number of required fields of that kind.
     */
    private int getNumberOfRequiredFields(final String field) {
    	int retval = 0;
    	final int size = getNumberOfField(field);
    	for (int j = 0; j<size; j++) {
    		if (isRequired(field,j)) {
    			retval++;
    		}
    	}
    	return retval;
    }

    private void checkIfForIllegalNumberOfFields(final DNFieldExtractor subjectdnfields, final DNFieldExtractor subjectaltnames, final DNFieldExtractor subjectdirattrs) throws EndEntityProfileValidationException {
    	// Check number of subjectdn fields.
    	final List<String> dnfields = DnComponents.getDnProfileFields();
    	final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
    	for (int i=0; i<dnfields.size(); i++) {
    		if (getNumberOfField(dnfields.get(i)) < subjectdnfields.getNumberOfFields(dnFieldExtractorIds.get(i))) {
    			throw new EndEntityProfileValidationException("Wrong number of " + dnfields.get(i) + " fields in Subject DN.");
    		}
    	}
    	// Check number of subject alternate name fields.
    	final List<String> altnamefields = DnComponents.getAltNameFields();
    	final List<Integer> altNameFieldExtractorIds = DnComponents.getAltNameDnIds();
    	for (int i=0; i<altnamefields.size(); i++) {
    		if (getNumberOfField(altnamefields.get(i)) < subjectaltnames.getNumberOfFields(altNameFieldExtractorIds.get(i))) {
    			throw new EndEntityProfileValidationException("Wrong number of " + altnamefields.get(i) + " fields in Subject Alternative Name.");
    		}
    	}
    	// Check number of subject directory attribute fields.
    	final List<String> dirattrfields = DnComponents.getDirAttrFields();
    	final List<Integer> dirAttrFieldExtractorIds = DnComponents.getDirAttrDnIds();
    	for (int i=0; i<dirattrfields.size(); i++) {
    		if (getNumberOfField(dirattrfields.get(i)) < subjectdirattrs.getNumberOfFields(dirAttrFieldExtractorIds.get(i))) {
    			throw new EndEntityProfileValidationException("Wrong number of " + dirattrfields.get(i) + " fields in Subject Directory Attributes.");
    		}
    	}
    }
    
    private void checkWithValidators(final DNFieldExtractor subjectdnfields, final DNFieldExtractor subjectaltnames) throws EndEntityProfileValidationException {
        final List<String> dnfields = DnComponents.getDnProfileFields();
        final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
        for (int i=0; i<dnfields.size(); i++) {
            final int dnId = dnFieldExtractorIds.get(i);
            final int profileId = DnComponents.dnIdToProfileId(dnId);
            final String fieldName = dnfields.get(i);
            final int num = subjectdnfields.getNumberOfFields(dnId);
            for (int j = 0; j < num; j++) {
                final Map<String,Serializable> validators = getValidation(profileId, j);
                if (validators != null) {
                    final String fieldValue = subjectdnfields.getField(dnId, j);
                    try {
                        EndEntityValidationHelper.checkValue(fieldName, validators, fieldValue);
                    } catch (EndEntityFieldValidatorException e) {
                        throw new EndEntityProfileValidationException("Did not pass validation of field " + fieldName + " (in DN). " + e.getMessage());
                    }
                }
            }
        }
        
        final List<String> sanfields = DnComponents.getAltNameFields();
        final List<Integer> sanFieldExtractorIds = DnComponents.getAltNameDnIds();
        for (int i=0; i<sanfields.size(); i++) {
            final int dnId = sanFieldExtractorIds.get(i);
            final int profileId = DnComponents.dnIdToProfileId(dnId);
            final String fieldName = sanfields.get(i);
            final int num = subjectaltnames.getNumberOfFields(dnId);
            for (int j = 0; j < num; j++) {
                final Map<String,Serializable> validators = getValidation(profileId, j);
                if (validators != null) {
                    final String fieldValue = subjectaltnames.getField(dnId, j);
                    try {
                        EndEntityValidationHelper.checkValue(fieldName, validators, fieldValue);
                    } catch (EndEntityFieldValidatorException e) {
                        throw new EndEntityProfileValidationException("Did not pass validation of field " + fieldName + " (in SAN). " + e.getMessage());
                    }
                }
            }
        }
    }

	/** methods for mapping the DN, AltName, DirAttr constants from string->number 
	 * @return number from profilemappings.properties, or -1 if the parameter does not exist
	 */
	private static int getParameterNumber(final String parameter) {
		final Integer number = dataConstants.get(parameter);
		if (number != null) {
			return number;			
		}
		if (log.isDebugEnabled()) {
		    log.warn("No parameter number for "+parameter, new Exception("Stacktrace"));
		} else {
		    log.warn("No parameter number for "+parameter);
		}
		return -1;
	}

	/** methods for mapping the DN, AltName, DirAttr constants from number->string */
	private static String getParameter(final int parameterNumber) {
		String ret = null;
		for (final Entry<String, Integer> entry : dataConstants.entrySet()) {
			if (entry.getValue() == parameterNumber) {
				ret = entry.getKey();
				break;
			}
		}
		if (ret == null) {
		    if (log.isDebugEnabled()) {
	            log.warn("No parameter for "+parameterNumber, new Exception("Stacktrace"));
	        } else {
	            log.warn("No parameter for "+parameterNumber);
	        }
		}
		return ret;
	}
	
    private void incrementFieldnumber(final int parameter){
    	@SuppressWarnings("unchecked")
        final ArrayList<Integer> numberarray = (ArrayList<Integer>) data.get(NUMBERARRAY);
    	numberarray.set(parameter, numberarray.get(parameter) + 1);
    }

    private void decrementFieldnumber(final int parameter){
    	@SuppressWarnings("unchecked")
        final ArrayList<Integer> numberarray = (ArrayList<Integer>) data.get(NUMBERARRAY);
    	numberarray.set(parameter, numberarray.get(parameter) - 1);
    }

    public static String[] getSubjectDNProfileFields() {
    	return DnComponents.getDnProfileFields().toArray(new String[0]);
    }

    public static String[] getSubjectAltnameProfileFields() {
    	return DnComponents.getAltNameFields().toArray(new String[0]);
    }

    public static String[] getSubjectDirAttrProfileFields() {
    	return DnComponents.getDirAttrFields().toArray(new String[0]);
    }

    public boolean isNameConstraintsPermittedUsed() {
        return getUse(NAMECONSTRAINTS_PERMITTED, 0);
    }

    public void setNameConstraintsPermittedUsed(final boolean use) {
        setUse(NAMECONSTRAINTS_PERMITTED, 0, use);
    }

    public boolean isNameConstraintsPermittedRequired() {
        return isRequired(NAMECONSTRAINTS_PERMITTED, 0);
    }

    public void setNameConstraintsPermittedRequired(final boolean required) {
        setRequired(NAMECONSTRAINTS_PERMITTED, 0, required);
    }

    public boolean isNameConstraintsExcludedUsed() {
        return getUse(NAMECONSTRAINTS_EXCLUDED, 0);
    }

    public void setNameConstraintsExcludedUsed(final boolean use) {
        setUse(NAMECONSTRAINTS_EXCLUDED, 0, use);
    }

    public boolean isNameConstraintsExcludedRequired() {
        return isRequired(NAMECONSTRAINTS_EXCLUDED, 0);
    }

    public void setNameConstraintsExcludedRequired(final boolean required) {
        setRequired(NAMECONSTRAINTS_EXCLUDED, 0, required);
    }
    
    public String getCabfOrganizationIdentifier() {
        return getValue(CABFORGANIZATIONIDENTIFIER, 0);
    }

    public void setCabfOrganizationIdentifier(final String value) {
        setValue(CABFORGANIZATIONIDENTIFIER, 0, value);
    }
    
    public boolean isCabfOrganizationIdentifierUsed() {
        return getUse(CABFORGANIZATIONIDENTIFIER, 0);
    }

    public void setCabfOrganizationIdentifierUsed(final boolean use) {
        setUse(CABFORGANIZATIONIDENTIFIER, 0, use);
    }
    
    public boolean isCabfOrganizationIdentifierModifiable() {
        return isModifyable(CABFORGANIZATIONIDENTIFIER, 0);
    }

    public void setCabfOrganizationIdentifierModifiable(final boolean modifiable) {
        setModifyable(CABFORGANIZATIONIDENTIFIER, 0, modifiable);
    }

    public boolean isCabfOrganizationIdentifierRequired() {
        return isRequired(CABFORGANIZATIONIDENTIFIER, 0);
    }

    public void setCabfOrganizationIdentifierRequired(final boolean required) {
        setRequired(CABFORGANIZATIONIDENTIFIER, 0, required);
    }

    /**
     * @return true if it should be possible to add extension data in the GUI.
     */
    public boolean getUseExtensiondata() {
        return getValueDefaultFalse(USEEXTENSIONDATA);
    }

    public void setUseExtensiondata(final boolean use){
    	data.put(USEEXTENSIONDATA, use);
    }
    
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Values={");
        for(String key : dataConstants.keySet()) {
            //Output all defined values
            Object value = data.get(key);
            if(value != null) {
                stringBuilder.append("[" + key + "=" + value + "]");
            }
        }
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
    
    /** 
     * Nested class FieldInstance for convenient invoking from xhtml
     */
    public class FieldInstance{
        private String name;
        private int number;
        private String value;
        private String defaultValue;
        private int profileId;
        private boolean rfcEmailUsed;
        private boolean dnsCopyCheckbox;
        String regexPattern;
        public FieldInstance(String name, int number){
            this.name = name;
            this.number = number;
            this.defaultValue = EndEntityProfile.this.getValue(name, number);
            this.value = isSelectable() ? getSelectableValues().get(0) : defaultValue;
            this.profileId = EndEntityProfile.dataConstants.get(name);
            this.rfcEmailUsed = name.equals("RFC822NAME") && isUsed();
            this.dnsCopyCheckbox = name.equals(DnComponents.DNSNAME) && isCopy();
            if (dnsCopyCheckbox) this.value = "";
            HashMap<String, Serializable> temp = EndEntityProfile.this.getValidation(name, number);
            if(temp != null){
                this.regexPattern =  (String)temp.get(RegexFieldValidator.class.getName());
            }
        }
        public boolean isUsed() {return EndEntityProfile.this.getUse(name, number);}
        public boolean isCopy() {return EndEntityProfile.this.getCopy(name, number);}
        public boolean isRequired() {return EndEntityProfile.this.isRequired(name, number);}
        public boolean isModifiable() {return EndEntityProfile.this.isModifyable(name, number);}
        public boolean isRegexPatternRequired() {return getRegexPattern() != null;}
        public boolean isUnModifiableUpnRfc() {
            return !isModifiable() && (name.equals("RFC822NAME") || name.equals("UPN"));
        }
        public boolean isRfcUseEmail() {
            return name.equals("RFC822NAME") && isUsed();
        }
        public boolean getRfcEmailUsed() {return rfcEmailUsed;}
        public void setRfcEmailUsed(boolean rfcEmailUsed) {this.rfcEmailUsed = rfcEmailUsed;}
        public boolean isCopyDns() {
            return name.equals(DnComponents.DNSNAME) && isCopy();
        }
        public boolean isDnsCopyCheckbox() {
            return dnsCopyCheckbox;
        }
        public void setDnsCopyCheckbox(boolean dnsCopyCheckbox) {
            this.dnsCopyCheckbox = dnsCopyCheckbox;
        }
        public String getValue(){return value;}
        public void setValue(String value){this.value = value;}
        public String getDefaultValue(){return defaultValue;}
        public void setDefaultValue(String value){this.defaultValue = value;}
        public String getName(){return name;}
        public String getRegexPattern(){return regexPattern;}
        public int getNumber(){return number;}
        public boolean isSelectable(){
            return !isModifiable() && getDefaultValue() != null && getDefaultValue().split(";").length > 1;
        }
        public List<String> getSelectableValues(){
            return isSelectable() ? Arrays.asList(defaultValue.split(";")) : null;
        }
        public List<String> getSelectableValuesUpnRfc(){
            return Arrays.asList(defaultValue.split(";"));
        }
        @Override
        public int hashCode(){return name.hashCode();}
        public int getProfileId(){return profileId;}
    }
    
    /** 
     * Nested method wrapper class Field for convenient invoking from xhtml
     */
    public class Field{
        private String name;
        private List<FieldInstance> instances;
        public Field(String name){
            this.name = name;
            int numberOfInstances = EndEntityProfile.this.getNumberOfField(name);
            instances = new ArrayList<>(numberOfInstances);
            for(int i=0; i<numberOfInstances; i++){
                instances.add(new FieldInstance(name, i));
            }
        }
        public int getNumber(){return instances.size();}
        public String getName(){return name;}
        public List<FieldInstance> getInstances(){return instances;}
    }
    public Field getUsername(){return new Field(EndEntityProfile.USERNAME);};
    public Field getPassword(){return new Field(EndEntityProfile.PASSWORD);};
    public Field getEmail(){return new Field(EndEntityProfile.EMAIL);};
}
