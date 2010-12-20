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

import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.StringTools;
import org.ejbca.util.dn.DNFieldExtractor;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.passgen.PasswordGeneratorFactory;


/**
 * The model representation of an end entity profile, used in in the ra module
 * of ejbca web interface.
 * 
 * The algorithm for constants in the EndEntityProfile is:
 * Values are stored as 100*parameternumber+parameter, so the first COMMONNAME value is 105, the second 205 etc.
 * Use flags are stored as 10000+100*parameternumber+parameter, so the first USE_COMMONNAME value is 10105, the second 10205 etc.
 * Required flags are stored as 20000+100*parameternumber+parameter, so the first REQUIRED_COMMONNAME value is 20105, the second 20205 etc.
 * Modifyable flags are stored as 30000+100*parameternumber+parameter, so the first MODIFYABLE_COMMONNAME value is 30105, the second 30205 etc.
 * 
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class EndEntityProfile extends UpgradeableDataHashMap implements java.io.Serializable, Cloneable {

    private static final Logger log = Logger.getLogger(EndEntityProfile.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 12;

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
    
    // Public constants
    /** Constant values for end entity profile. */
    private static HashMap<String, Integer> dataConstants = new HashMap<String, Integer>();


    // Field constants, used in the map below
    public static final String USERNAME           = "USERNAME";
    public static final String PASSWORD           = "PASSWORD";
    public static final String CLEARTEXTPASSWORD  = "CLEARTEXTPASSWORD";
    public static final String AUTOGENPASSWORDTYPE   = "AUTOGENPASSWORDTYPE";
    public static final String AUTOGENPASSWORDLENGTH = "AUTOGENPASSWORDLENGTH";
    
    public static final String EMAIL              = "EMAIL";
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
    public static final String CERTSERIALNR       = "CERTSERIALNR";
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

    // Default values
    // These must be in a strict order that can never change 
    // Custom values configurable in a properties file (profilemappings.properties)
    static {
    	dataConstants.put(USERNAME, Integer.valueOf(0));
    	dataConstants.put(PASSWORD, Integer.valueOf(1));
    	dataConstants.put(CLEARTEXTPASSWORD, Integer.valueOf(2));
    	dataConstants.put(AUTOGENPASSWORDTYPE, Integer.valueOf(95));
    	dataConstants.put(AUTOGENPASSWORDLENGTH, Integer.valueOf(96));
        // DN components
    
    	dataConstants.put(EMAIL, Integer.valueOf(26));
    	dataConstants.put(KEYRECOVERABLE, Integer.valueOf(28));
    	dataConstants.put(DEFAULTCERTPROFILE, Integer.valueOf(29));
    	dataConstants.put(AVAILCERTPROFILES, Integer.valueOf(30));
    	dataConstants.put(DEFKEYSTORE, Integer.valueOf(31));
    	dataConstants.put(AVAILKEYSTORE, Integer.valueOf(32));
    	dataConstants.put(DEFAULTTOKENISSUER, Integer.valueOf(33));
    	dataConstants.put(AVAILTOKENISSUER, Integer.valueOf(34));
    	dataConstants.put(SENDNOTIFICATION, Integer.valueOf(35));

    	dataConstants.put(DEFAULTCA, Integer.valueOf(37));
    	dataConstants.put(AVAILCAS, Integer.valueOf(38));
    	
    	// Load all DN, altName and directoryAttributes from DnComponents.
    	dataConstants.putAll(DnComponents.getProfilenameIdMap());
    	
    	dataConstants.put(ISSUANCEREVOCATIONREASON, Integer.valueOf(94));
    	dataConstants.put(ALLOWEDREQUESTS, Integer.valueOf(97));
    	dataConstants.put(STARTTIME, Integer.valueOf(98));
    	dataConstants.put(ENDTIME, Integer.valueOf(99));
    	dataConstants.put(CARDNUMBER, Integer.valueOf(91));
    	dataConstants.put(MAXFAILEDLOGINS, Integer.valueOf(93));
    	dataConstants.put(CERTSERIALNR, Integer.valueOf(92));
    }
    // Type of data constants.
    private static final int VALUE      = 0;
    private static final int USE        = 1;
    private static final int ISREQUIRED = 2;
    private static final int MODIFYABLE = 3;

    public static final String SPLITCHAR       = ";";

    public static final String TRUE  = "true";
    public static final String FALSE = "false";
    


    // Constants used with field ordering
    public static final int FIELDTYPE = 0;
    public static final int NUMBER    = 1;

    // Public methods.
    /** Creates a new instance of EndEntity Profile */
    public EndEntityProfile() {
      super();

      // Set default required fields.
      init(false);
    }

    /** Creates a default empty end entity profile with all standard fields added to it. */
    public  EndEntityProfile(boolean emptyprofile){
      super();

      init(emptyprofile);
    }

    private void init(boolean emptyprofile){
    	// Find out the max value in dataConstants
        int max = 0;
        Collection ids = dataConstants.values();
        Iterator it = ids.iterator();
        while (it.hasNext()) {
        	Integer id = (Integer)it.next();
			if (max < id) {
				max = id;
			}        	
        }
        // Common initialization of profile
        if (log.isDebugEnabled()) {
        	log.debug("The highest number in dataConstants is: "+max);
        }
        ArrayList numberoffields = new ArrayList(max);
        for(int i =0; i <= max; i++){
          numberoffields.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY,numberoffields);
        data.put(SUBJECTDNFIELDORDER,new ArrayList());
        data.put(SUBJECTALTNAMEFIELDORDER,new ArrayList());
        data.put(SUBJECTDIRATTRFIELDORDER,new ArrayList());
        
      if(emptyprofile){
        Set keySet = dataConstants.keySet();
        Iterator iter = keySet.iterator();
        while (iter.hasNext()) {
        	String key = (String)iter.next();
        	if (key.equals(SENDNOTIFICATION) || key.equals(DnComponents.OTHERNAME)
        	    || key.equals(DnComponents.X400ADDRESS) || key.equals(DnComponents.EDIPARTNAME) || key.equals(DnComponents.REGISTEREDID)) {
        		continue;
        	} else {
                addField(key);
                setValue(key,0,"");
                setRequired(key,0,false);
                setUse(key,0,true);
                setModifyable(key,0,true);        		
        	}
        }
        // Add another DC-field since (if used) more than one is always used
        addField(DnComponents.DOMAINCOMPONENT);
        setValue(DnComponents.DOMAINCOMPONENT,1,"");
        setRequired(DnComponents.DOMAINCOMPONENT,1,false);
        setUse(DnComponents.DOMAINCOMPONENT,1,true);
        setModifyable(DnComponents.DOMAINCOMPONENT,1,true);
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
        setValue(DEFAULTCERTPROFILE,0, "" + SecConst.CERTPROFILE_FIXED_ENDUSER);
        setValue(AVAILCERTPROFILES,0, SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + SecConst.CERTPROFILE_FIXED_OCSPSIGNER + ";" + SecConst.CERTPROFILE_FIXED_SERVER);
        setValue(DEFKEYSTORE,0, "" + SecConst.TOKEN_SOFT_BROWSERGEN);
        setValue(AVAILKEYSTORE,0, SecConst.TOKEN_SOFT_BROWSERGEN + ";" + SecConst.TOKEN_SOFT_P12 +  ";" + SecConst.TOKEN_SOFT_JKS + ";" + SecConst.TOKEN_SOFT_PEM);
        setValue(AVAILCAS,0, Integer.toString(SecConst.ALLCAS));
        setValue(ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);
        // Do not use hard token issuers by default.
        setUse(AVAILTOKENISSUER, 0, false);
        setUse(STARTTIME,0,false);
        setUse(ENDTIME,0,false);
        setUse(ALLOWEDREQUESTS,0,false);
        setUse(CARDNUMBER,0,false);
        setUse(ISSUANCEREVOCATIONREASON,0,false);
        setUse(MAXFAILEDLOGINS,0,false);
        
      }else{
         // initialize profile data
         addField(USERNAME);
         addField(PASSWORD);
         addField(AUTOGENPASSWORDTYPE);
         addField(AUTOGENPASSWORDLENGTH);
         addField(DnComponents.COMMONNAME);
         addField(EMAIL);
         addField(DEFAULTCERTPROFILE);
         addField(AVAILCERTPROFILES);
         addField(DEFKEYSTORE);
         addField(AVAILKEYSTORE);
         addField(DEFAULTTOKENISSUER);
         addField(AVAILTOKENISSUER);
         addField(AVAILCAS);
         addField(DEFAULTCA);         
         addField(STARTTIME);         
         addField(ENDTIME);         
         addField(ALLOWEDREQUESTS);
         addField(CARDNUMBER);
         addField(ISSUANCEREVOCATIONREASON);
         addField(MAXFAILEDLOGINS);
         
         setRequired(USERNAME,0,true);
         setRequired(PASSWORD,0,true);
         setRequired(DnComponents.COMMONNAME,0,true);
         setRequired(DEFAULTCERTPROFILE,0,true);
         setRequired(AVAILCERTPROFILES,0,true);
         setRequired(DEFKEYSTORE,0,true);
         setRequired(AVAILKEYSTORE,0,true);
         setRequired(DEFAULTCA,0,true);
         setRequired(AVAILCAS,0,true);
         setRequired(STARTTIME,0,false);
         setRequired(ENDTIME,0,false);
         setRequired(ALLOWEDREQUESTS,0,false);
         setRequired(CARDNUMBER,0,false);
         setRequired(ISSUANCEREVOCATIONREASON,0,false);
         setRequired(MAXFAILEDLOGINS, 0, false);
      
         setValue(AUTOGENPASSWORDLENGTH, 0, "8");
         setValue(DEFAULTCERTPROFILE,0, "" + SecConst.CERTPROFILE_FIXED_ENDUSER);
         setValue(AVAILCERTPROFILES,0, SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + SecConst.CERTPROFILE_FIXED_SUBCA + ";" + SecConst.CERTPROFILE_FIXED_ROOTCA);
         setValue(DEFKEYSTORE,0, "" + SecConst.TOKEN_SOFT_BROWSERGEN);
         setValue(AVAILKEYSTORE,0, SecConst.TOKEN_SOFT_BROWSERGEN + ";" + SecConst.TOKEN_SOFT_P12 +  ";" + SecConst.TOKEN_SOFT_JKS + ";" + SecConst.TOKEN_SOFT_PEM);
         setValue(ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);

         // Do not use hard token issuers by default.
         setUse(AVAILTOKENISSUER, 0, false);
         setUse(STARTTIME,0,false);
         setUse(ENDTIME,0,false);
         setUse(ALLOWEDREQUESTS,0,false);
         setUse(CARDNUMBER,0,false);
         setUse(ISSUANCEREVOCATIONREASON,0,false);
         setUse(MAXFAILEDLOGINS,0,false);

      }
    }

    public void addField(String parameter){
    	addField(getParameterNumber(parameter));
    }
    /**
     * Function that adds a field to the profile.
     *
     * @param paramter is the field and one of the field constants.
     */
    public void addField(int parameter){
      int size =  getNumberOfField(parameter);
      setValue(parameter,size,"");
      setRequired(parameter,size,false);
      setUse(parameter,size,true);
      setModifyable(parameter,size,true);
      String param = getParameter(parameter);
      ArrayList dns = DnComponents.getDnProfileFields();
      if(dns.contains(param)){
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
        Integer val = Integer.valueOf((NUMBERBOUNDRARY*parameter) + size);
        fieldorder.add(val);
      }
      ArrayList altNames = DnComponents.getAltNameFields();
      if(altNames.contains(param)) {
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
        Integer val = Integer.valueOf((NUMBERBOUNDRARY*parameter) + size);
        fieldorder.add(val);
      }
      ArrayList dirAttrs = DnComponents.getDirAttrFields();
      if(dirAttrs.contains(param)){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
          Integer val = Integer.valueOf((NUMBERBOUNDRARY*parameter) + size);
          fieldorder.add(val);
        }
      incrementFieldnumber(parameter);
    }

    public void removeField(String parameter, int number){
    	removeField(getParameterNumber(parameter), number);
    }
    /**
     * Function that removes a field from the end entity profile.
     *
     * @param parameter is the field to remove.
     * @param number is the number of field.
     */
    public void removeField(int parameter, int number){
      // Remove field and move all file ids above.
      int size =  getNumberOfField(parameter);

      if(size>0){
        for(int n = number; n < size-1; n++){
          setValue(parameter,n,getValue(parameter,n+1));
          setRequired(parameter,n,isRequired(parameter,n+1));
          setUse(parameter,n,getUse(parameter,n+1));
          setModifyable(parameter,n,isModifyable(parameter,n+1));
        }

        String param = getParameter(parameter);
        // Remove last element from Subject DN order list.
        ArrayList dns = DnComponents.getDnProfileFields();
        if(dns.contains(param)){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
          int value = (NUMBERBOUNDRARY*parameter) + size -1;
          for(int i=0; i < fieldorder.size(); i++){
             if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                fieldorder.remove(i);
                break;
             }
          }
        }
        // Remove last element from Subject AltName order list.
        ArrayList altNames = DnComponents.getAltNameFields();
        if(altNames.contains(param)) {
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
          int value = (NUMBERBOUNDRARY*parameter) + size -1;	//number;
          for(int i=0; i < fieldorder.size(); i++){
             if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                fieldorder.remove(i);
                break;
             }
          }
        }
        // Remove last element from Subject DirAttr order list.
        ArrayList dirAttrs = DnComponents.getDirAttrFields();
        if(dirAttrs.contains(param)){
            ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
            int value = (NUMBERBOUNDRARY*parameter) + size -1;	//number;
            for(int i=0; i < fieldorder.size(); i++){
               if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                  fieldorder.remove(i);
                  break;
               }
            }
          }
        // Remove last element of the type from hashmap
        data.remove(Integer.valueOf((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*(size-1)) + parameter));
        data.remove(Integer.valueOf((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*(size-1)) + parameter));
        data.remove(Integer.valueOf((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*(size-1)) + parameter));
        data.remove(Integer.valueOf((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*(size-1)) + parameter));

        decrementFieldnumber(parameter);
      }
    }

    /**
     * Function that returns the number of one kind of field in the profile.
     *
     */
    protected int getNumberOfField(String parameter){
    	return getNumberOfField(getParameterNumber(parameter));
    }
    private int getNumberOfField(int parameter){
    	ArrayList arr = checkAndUpgradeWithNewFields(parameter);
    	return ((Integer) arr.get(parameter)).intValue();
    }

	private ArrayList checkAndUpgradeWithNewFields(int parameter) {
		ArrayList arr = (ArrayList)data.get(NUMBERARRAY);
    	// This is an automatic upgrade function, if we have dynamically added new fields
    	if (parameter >= arr.size()) {
			String msg = intres.getLocalizedMessage("ra.eeprofileaddfield", Integer.valueOf(parameter));
    		log.debug(msg);
    		for (int i = arr.size(); i <= parameter; i++) {
                arr.add(Integer.valueOf(0));
    		}
            data.put(NUMBERARRAY,arr);
    	}
		return arr;
	}
    

    public void setValue(int parameter, int number, String value) {
        if(value !=null){
            value=value.trim();
            data.put(Integer.valueOf((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), value);
         }else{
            data.put(Integer.valueOf((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), "");
         }
    }
    public void setValue(String parameter, int number, String value) {
    	setValue(getParameterNumber(parameter), number, value);
    }

    public void setUse(int parameter, int number, boolean use){
          data.put(Integer.valueOf((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(use));
    }
    public void setUse(String parameter, int number, boolean use){
    	setUse(getParameterNumber(parameter), number, use);
    }

    public void setRequired(int parameter, int number,  boolean isrequired) {
    	data.put(Integer.valueOf((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(isrequired));
    }
    public void setRequired(String parameter, int number,  boolean isrequired) {
    	setRequired(getParameterNumber(parameter), number, isrequired);
    }

    public void setModifyable(int parameter, int number, boolean changeable) {
    	data.put(Integer.valueOf((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(changeable));
    }
    public void setModifyable(String parameter, int number, boolean changeable) {
    	setModifyable(getParameterNumber(parameter), number, changeable);
    }

    public String getValue(int parameter, int number) {
        String returnval = (String) data.get(Integer.valueOf((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null){
            return returnval;
        }
        return "";
    }
    public String getValue(String parameter, int number) {
    	return getValue(getParameterNumber(parameter), number);
    }

    public boolean getUse(int parameter, int number){
        Boolean returnval = (Boolean) data.get(Integer.valueOf((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null){
            return returnval.booleanValue();
        }
            return false;
    }
    public boolean getUse(String parameter, int number){
    	return getUse(getParameterNumber(parameter), number);
    }

    public boolean isRequired(int parameter, int number) {
        Boolean returnval = (Boolean) data.get(Integer.valueOf((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null){
            return returnval.booleanValue();
        }
            return false;
    }
    public boolean isRequired(String parameter, int number) {
    	return isRequired(getParameterNumber(parameter), number);
    }

    public boolean isModifyable(int parameter, int number){
        Boolean returnval = (Boolean) data.get(Integer.valueOf((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null){
            return returnval.booleanValue();
        }
        return false;
    }
    public boolean isModifyable(String parameter, int number) {
    	return isModifyable(getParameterNumber(parameter), number);
    }

    public int getSubjectDNFieldOrderLength(){
      return ((ArrayList) data.get(SUBJECTDNFIELDORDER)).size();
    }
    public int getSubjectAltNameFieldOrderLength(){
      return ((ArrayList) data.get(SUBJECTALTNAMEFIELDORDER)).size();
    }
    public int getSubjectDirAttrFieldOrderLength(){
        return ((ArrayList) data.get(SUBJECTDIRATTRFIELDORDER)).size();
      }

    /** returns two int : the first is the DN field which is a constant in DN field extractor,
     * the second is in which order the attribute is, 0 is first OU and 1 can mean second OU (if OU is specified in the first value).
     * 
     */
    public int[] getSubjectDNFieldsInOrder(int index){
      int[] returnval = new int[2];
      ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
      returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % NUMBERBOUNDRARY;
      returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / NUMBERBOUNDRARY;

      return returnval;
    }

    public int[] getSubjectAltNameFieldsInOrder(int index){
      int[] returnval = new int[2];
      ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
      Integer i = (Integer)fieldorder.get(index);
      returnval[NUMBER] = i.intValue() % NUMBERBOUNDRARY;
      returnval[FIELDTYPE] = i.intValue() / NUMBERBOUNDRARY;

      return returnval;
    }

    public int[] getSubjectDirAttrFieldsInOrder(int index){
        int[] returnval = new int[2];
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
        returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % NUMBERBOUNDRARY;
        returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / NUMBERBOUNDRARY;

        return returnval;
      }

    /** Gets a Collection of available CA Ids (as Strings). 
     * Use String.valueOf(caidstring) to get the int value of the CA id.
     * 
     * @return a Collection of String, where the string is an integer (never null).
     */
    public Collection<String> getAvailableCAs(){
        ArrayList<String> availablecaids = new ArrayList<String>();
        availablecaids.addAll(Arrays.asList(getValue(AVAILCAS,0).split(SPLITCHAR)));
        return availablecaids;
    }
    
    /** Gets a Collection of available certificate profile ids
     * Use String.valueOf(caidstring) to get the int value
     * 
     * @return a Collection of String, where the string is an integer.
     */
    public Collection<String> getAvailableCertificateProfileIds() {
        ArrayList<String> profiles = new ArrayList<String>();
        String list = getValue(AVAILCERTPROFILES,0);
        if (list != null) {
            profiles.addAll(Arrays.asList(list.split(SPLITCHAR)));        	
        }
        return profiles;    	
    }

    public int getDefaultCA(){
    	int ret = -1;
    	String str = getValue(DEFAULTCA,0);
    	if (str != null && !StringUtils.isEmpty(str)) {
    		ret = Integer.valueOf(str);
    	}
        return ret;
    }
    
    public boolean useAutoGeneratedPasswd(){    	
    	return !this.getUse(EndEntityProfile.PASSWORD,0);
    }
    
    public String getAutoGeneratedPasswd(){
    	String type = getValue(AUTOGENPASSWORDTYPE, 0);
    	if (type == null || "".equals(type)) {
    		type = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
    	}
    	String length = getValue(AUTOGENPASSWORDLENGTH, 0);
    	if (length == null) {
    		length = "8";
    	}
    	int pwdlen = 8;
    	try {
        	pwdlen = Integer.parseInt(length);    		
    	} catch (NumberFormatException e) {
    		log.info("NumberFormatException parsing AUTOGENPASSWORDLENGTH, using default value of 8: ", e);
    	}
    	return PasswordGeneratorFactory.getInstance(type).getNewPassword(pwdlen, pwdlen);    	
    }
    
    /**
     * @return String value with types from org.ejbca.util.passgen, example org.ejbca.util.passgen.DigitPasswordGenerator.NAME (PWGEN_DIGIT)
     */
    public static Collection<String> getAvailablePasswordTypes() {
        return PasswordGeneratorFactory.getAvailablePasswordTypes();
    }

    // User notifications - begin
    public List<UserNotification> getUserNotifications() {
    	List<UserNotification> l = (List<UserNotification>)data.get(USERNOTIFICATIONS);
    	if (l == null) {
    		l = new ArrayList<UserNotification>();
    	}
    	return l;
    }

    public void addUserNotification(UserNotification notification) {
    	if (data.get(USERNOTIFICATIONS) == null) {
    		setUserNotifications(new ArrayList<UserNotification>(0));
    	}
    	((List<UserNotification>) data.get(USERNOTIFICATIONS)).add(notification);
    }

    public void setUserNotifications(List<UserNotification> notifications) {
    	if (notifications == null) {
    		data.put(USERNOTIFICATIONS, new ArrayList<UserNotification>(0));
    	} else {
    		data.put(USERNOTIFICATIONS, notifications);
    	}
    }

    public void removeUserNotification(UserNotification notification) {
    	if (data.get(USERNOTIFICATIONS) != null) {
    		((List<UserNotification>) data.get(USERNOTIFICATIONS)).remove(notification);
    	}
    }
    // User notifications - end

    /**
     * @return indicationg if the keyreccovered certificate should be reused or not.
     */
    public boolean getReUseKeyRevoceredCertificate(){
    	if(data.get(REUSECERTIFICATE) == null){
    		return false;
    	}
    	
    	return ((Boolean) data.get(REUSECERTIFICATE)).booleanValue();
    }
    
    public void setReUseKeyRevoceredCertificate(boolean reuse){
    	data.put(REUSECERTIFICATE, new Boolean(reuse));
    }
    
    /**
     * @return indicationg if the profile checks should be reversed or not.
     * default is false.
     */
    public boolean getReverseFieldChecks(){
    	if(data.get(REVERSEFFIELDCHECKS) == null){
    		return false;
    	}
    	
    	return ((Boolean) data.get(REVERSEFFIELDCHECKS)).booleanValue();
    }
    
    public void setReverseFieldChecks(boolean reverse){
    	data.put(REVERSEFFIELDCHECKS, new Boolean(reverse));
    }
    
    /**
     * @return indication if allows profile DN should merged to webservices.
     * default is false.
     */
    public boolean getAllowMergeDnWebServices(){
    	if(data.get(ALLOW_MERGEDN_WEBSERVICES) == null){
    		return false;
    	}
    	
    	return ((Boolean) data.get(ALLOW_MERGEDN_WEBSERVICES)).booleanValue();
    }
    
    public void setAllowMergeDnWebServices(boolean merge){
    	data.put(ALLOW_MERGEDN_WEBSERVICES, new Boolean(merge));
    }

    
    /**
     * @return indicationg printing of userdata should be done
     * default is false.
     */
    public boolean getUsePrinting(){
    	if(data.get(PRINTINGUSE) == null){
    		return false;
    	}
    	
    	return ((Boolean) data.get(PRINTINGUSE)).booleanValue();
    }
    
    public void setUsePrinting(boolean use){
    	data.put(PRINTINGUSE, new Boolean(use));
    }
    
    /**
     * @return indicationg printing of userdata should be done
     * default is false.
     */
    public boolean getPrintingDefault(){
    	if(data.get(PRINTINGDEFAULT) == null){
    		return false;
    	}
    	
    	return ((Boolean) data.get(PRINTINGDEFAULT)).booleanValue();
    }
    
    public void setPrintingDefault(boolean printDefault){
    	data.put(PRINTINGDEFAULT, new Boolean(printDefault));
    }
    
    /**
     * @return indicationg printing of userdata should be done
     * default is false.
     */
    public boolean getPrintingRequired(){
    	if(data.get(PRINTINGREQUIRED) == null){
    		return false;
    	}
    	return ((Boolean) data.get(PRINTINGREQUIRED)).booleanValue();
    }
    
    public void setPrintingRequired(boolean printRequired){
    	data.put(PRINTINGREQUIRED, new Boolean(printRequired));
    }
    
    /**
     * @return the number of copies that should be printed
     * default is 1.
     */
    public int getPrintedCopies(){
    	if(data.get(PRINTINGCOPIES) == null){
    		return 1;
    	}
    	
    	return ((Integer) data.get(PRINTINGCOPIES)).intValue();
    }
    
    public void setPrintedCopies(int copies){
    	data.put(PRINTINGCOPIES, Integer.valueOf(copies));
    }
    
    /**
     * @return the name of the printer that should be used
     */
    public String getPrinterName(){
    	if(data.get(PRINTINGPRINTERNAME) == null){
    		return "";
    	}
    	
    	return (String) data.get(PRINTINGPRINTERNAME);
    }
    
    public void setPrinterName(String printerName){
    	data.put(PRINTINGPRINTERNAME, printerName);
    }
    
    /**
     * @return filename of the uploaded 
     */
    public String getPrinterSVGFileName(){
    	if(data.get(PRINTINGSVGFILENAME) == null){
    		return "";
    	}
    	
    	return (String) data.get(PRINTINGSVGFILENAME);
    }
    
    public void setPrinterSVGFileName(String printerSVGFileName){
    	data.put(PRINTINGSVGFILENAME, printerSVGFileName);
    }
    
    /**
     * @return the data of the SVG file, if no content have
     * been uploaded null is returned
     */
    public String getPrinterSVGData(){
    	if(data.get(PRINTINGSVGDATA) == null){
    		return null;
    	}
    	
    	return new String(Base64.decode(((String) data.get(PRINTINGSVGDATA)).getBytes()));
    }
    
    public void setPrinterSVGData(String sVGData){
    	data.put(PRINTINGSVGDATA, new String(Base64.encode(sVGData.getBytes())));
    }
    
    
    public void doesUserFullfillEndEntityProfile(UserDataVO userdata, boolean clearpwd) throws UserDoesntFullfillEndEntityProfile {
    	doesUserFullfillEndEntityProfile(userdata.getUsername(), userdata.getPassword(), userdata.getDN(), userdata.getSubjectAltName(), "", userdata.getEmail(), 
    											userdata.getCertificateProfileId(), clearpwd, userdata.getKeyRecoverable(), userdata.getSendNotification(), 
    											userdata.getTokenType(), userdata.getHardTokenIssuerId(), userdata.getCAId(), userdata.getExtendedinformation());
    	
        //Checking if the cardnumber is required and set
        if(isRequired(CARDNUMBER,0)){
            if((userdata.getCardNumber() == null) || userdata.getCardNumber().equals("") || (userdata.getCardNumber().length() <= 0) ){
               throw new UserDoesntFullfillEndEntityProfile("Cardnumber is not set");
            }
         }
    }
    
    public void doesUserFullfillEndEntityProfile(String username, String password, String dn, String subjectaltname, String subjectdirattr, String email,  int certificateprofileid,
                                                 boolean clearpwd, boolean keyrecoverable, boolean sendnotification,
                                                 int tokentype, int hardwaretokenissuerid, int caid, ExtendedInformation ei)
       throws UserDoesntFullfillEndEntityProfile{

     if(useAutoGeneratedPasswd()){
	   if(password !=null){
		throw new UserDoesntFullfillEndEntityProfile("Autogenerated password must have password==null");
	   }
	   
	   
     }else{  
        if(!isModifyable(PASSWORD,0)){
          if(!password.equals(getValue(PASSWORD,0))){
            throw new UserDoesntFullfillEndEntityProfile("Password didn't match requirement of it's profile.");
          }
        }
        else
          if(isRequired(PASSWORD,0)){
            if(password == null || password.trim().equals("")){
              throw new UserDoesntFullfillEndEntityProfile("Password cannot be empty or null.");
            }
        }
     }
     
      if(!getUse(CLEARTEXTPASSWORD,0) && clearpwd) {
          throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be used.");
      }
      if(isRequired(CLEARTEXTPASSWORD,0)){
        if(getValue(CLEARTEXTPASSWORD,0).equals(TRUE) && !clearpwd){
           throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be false.");
        }
        if(getValue(CLEARTEXTPASSWORD,0).equals(FALSE) && clearpwd){
           throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be true.");
        }
     }

      doesUserFullfillEndEntityProfileWithoutPassword(username, dn, subjectaltname, subjectdirattr, email,
    		  certificateprofileid, keyrecoverable, sendnotification, tokentype, hardwaretokenissuerid, caid, ei);
    }

    public void doesUserFullfillEndEntityProfileWithoutPassword(String username,  String dn, String subjectaltname, String subjectdirattr,
    		String email,  int certificateprofileid, boolean keyrecoverable, boolean sendnotification,
    		int tokentype, int hardwaretokenissuerid, int caid, ExtendedInformation ei)
			throws UserDoesntFullfillEndEntityProfile {
    	if (log.isTraceEnabled()) {
    		log.trace(">doesUserFullfillEndEntityProfileWithoutPassword()");
    	}
      DNFieldExtractor subjectdnfields = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
      if (subjectdnfields.isIllegal()) {
          throw new UserDoesntFullfillEndEntityProfile("Subject DN is illegal.");
      }
      DNFieldExtractor subjectaltnames   = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
      if (subjectaltnames.isIllegal()) {
          throw new UserDoesntFullfillEndEntityProfile("Subject alt names are illegal.");
      }
      DNFieldExtractor subjectdirattrs   = new DNFieldExtractor(subjectdirattr, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
      if (subjectdirattrs.isIllegal()) {
          throw new UserDoesntFullfillEndEntityProfile("Subject directory attributes are illegal.");
      }

      // Check that no other than supported dn fields exists in the subject dn.
      if(subjectdnfields.existsOther()) {
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject DN Field found in:" + dn);
      }
      if(subjectaltnames.existsOther()) {
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject Alternate Name Field found in:" + subjectaltname );
      }
      if(subjectdirattrs.existsOther()) {
          throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject Directory Attribute Field found in:" + subjectdirattr );
      }
      checkIfAllRequiredFieldsExists(subjectdnfields, subjectaltnames, subjectdirattrs, username, email);

      // Make sure that there are enough fields to cover all required in profile
      checkIfForIllegalNumberOfFields(subjectdnfields, subjectaltnames, subjectdirattrs);

      // Check contents of username.
      checkIfDataFullfillProfile(USERNAME,0,username, "Username",null);

      //  Check Email address.
     if(email == null){
       email = "";
     }
     checkIfDomainFullfillProfile(EMAIL,0,email,"Email");

     // Make sure that every value has a corresponding field in the entity profile
     checkIfFieldsMatch(subjectdnfields, DNFieldExtractor.TYPE_SUBJECTDN, email); 
     checkIfFieldsMatch(subjectaltnames, DNFieldExtractor.TYPE_SUBJECTALTNAME, email);
     
      // Check contents of Subject Directory Attributes fields.
      HashMap subjectdirattrnumbers = subjectdirattrs.getNumberOfFields();
      Integer[] dirattrids = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDIRATTR);
      for(int i = 0; i < dirattrids.length; i++){
    	  Integer dirattrid = dirattrids[i];
		  int nof = ((Integer)subjectdirattrnumbers.get(dirattrid)).intValue();
    	  for(int j=0; j < nof; j++){
    		  checkForIllegalChars(subjectdirattrs.getField(dirattrid.intValue(),j));
    		  if(dirattrid.intValue() == DNFieldExtractor.COUNTRYOFCITIZENSHIP){
    			  checkIfISO3166FullfillProfile(DnComponents.COUNTRYOFCITIZENSHIP,j,subjectdirattrs.getField(dirattrid.intValue(),j),"COUNTRYOFCITIZENSHIP");
    		  } else if(dirattrid.intValue() == DNFieldExtractor.COUNTRYOFRESIDENCE){
    			  checkIfISO3166FullfillProfile(DnComponents.COUNTRYOFRESIDENCE,j,subjectdirattrs.getField(dirattrid.intValue(),j),"COUNTRYOFRESIDENCE");
    		  } else if(dirattrid.intValue() == DNFieldExtractor.DATEOFBIRTH){
    			  checkIfDateFullfillProfile(DnComponents.DATEOFBIRTH,j,subjectdirattrs.getField(dirattrid.intValue(),j),"DATEOFBIRTH");
    		  } else if(dirattrid.intValue() == DNFieldExtractor.GENDER){
    			  checkIfGenderFullfillProfile(DnComponents.GENDER,j,subjectdirattrs.getField(dirattrid.intValue(),j),"GENDER");
    		  }else{
    			  checkIfDataFullfillProfile(DnComponents.dnIdToProfileName(dirattrid.intValue()),j,subjectdirattrs.getField(dirattrid.intValue(),j), DnComponents.getErrTextFromDnId(dirattrid.intValue()), email);
    		  }   
    	  }
      }

      // Check for keyrecoverable flag.
      if(!getUse(KEYRECOVERABLE,0) &&  keyrecoverable) {
    	  throw new UserDoesntFullfillEndEntityProfile("Key Recoverable cannot be used.");
      }
      if(isRequired(KEYRECOVERABLE,0)){
    	  if(getValue(KEYRECOVERABLE,0).equals(TRUE) && !keyrecoverable) {
    		  throw new UserDoesntFullfillEndEntityProfile("Key Recoverable is required.");
    	  }
    	  if(getValue(KEYRECOVERABLE,0).equals(FALSE) && keyrecoverable) {
    		  throw new UserDoesntFullfillEndEntityProfile("Key Recoverable cannot be set in current end entity profile.");
    	  }
      }

   // Check for send notification flag.
      if(!getUse(SENDNOTIFICATION,0) &&  sendnotification){
    	  throw new UserDoesntFullfillEndEntityProfile("Email notification cannot be used.");
      }
      if(isRequired(SENDNOTIFICATION,0)){
    	  if(getValue(SENDNOTIFICATION,0).equals(TRUE) && !sendnotification){
    		  throw new UserDoesntFullfillEndEntityProfile("Email notification is required.");
    	  }
    	  if(getValue(SENDNOTIFICATION,0).equals(FALSE) && sendnotification) {
    		  throw new UserDoesntFullfillEndEntityProfile("Email notification cannot be set in current end entity profile.");
    	  }
      }

      // Check if certificate profile is among available certificate profiles.
      String[] availablecertprofiles;
      try{
        availablecertprofiles = getValue(AVAILCERTPROFILES,0).split(SPLITCHAR);
      }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablecertprofiles == null) {
           throw new UserDoesntFullfillEndEntityProfile("Error Available certificate profiles is null.");
      }
      boolean certprofilefound=false;
      for(int i=0; i < availablecertprofiles.length;i++){
          if( Integer.parseInt(availablecertprofiles[i]) == certificateprofileid) {
        	  certprofilefound=true;
          }
      }
      
      if(!certprofilefound) {
          throw new UserDoesntFullfillEndEntityProfile("Couldn't find certificate profile ("+certificateprofileid+") among available certificate profiles.");
      }
      // Check if tokentype is among available  token types.
      String[] availablesofttokentypes;
      try{
        availablesofttokentypes = getValue(AVAILKEYSTORE,0).split(SPLITCHAR);
      }catch(Exception e){
        throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablesofttokentypes == null) {
          throw new UserDoesntFullfillEndEntityProfile("Error available  token types is null.");
      }
      boolean softtokentypefound=false;
      for(int i=0; i < availablesofttokentypes.length;i++){
          if( Integer.parseInt(availablesofttokentypes[i]) == tokentype) {
        	  softtokentypefound=true;
          }
      }
      if(!softtokentypefound) {
    	  throw new UserDoesntFullfillEndEntityProfile("Soft token type is not available in End Entity Profile.");
      }

      // If soft token check for hardwaretoken issuer id = 0.
      if(tokentype <= SecConst.TOKEN_SOFT){
        if(hardwaretokenissuerid != 0) {
           throw new UserDoesntFullfillEndEntityProfile("Soft tokens cannot have a hardware token issuer.");
        }
      }
      // If Hard token type check if hardware token issuer is among available hardware token issuers.
      if(tokentype > SecConst.TOKEN_SOFT && getUse(AVAILTOKENISSUER, 0) ){ // Hardware token.
        String[] availablehardtokenissuers;
        try{
          availablehardtokenissuers = getValue(AVAILTOKENISSUER, 0).split(SPLITCHAR);
        }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
        }
        if(availablehardtokenissuers == null) {
            throw new UserDoesntFullfillEndEntityProfile("Error available hard token issuers is null.");
        }
        boolean hardtokentypefound=false;
        for(int i=0; i < availablehardtokenissuers.length;i++){
            if( Integer.parseInt(availablehardtokenissuers[i]) == hardwaretokenissuerid) {
            	hardtokentypefound=true;
            }
        }
        
        if(!hardtokentypefound) {
            throw new UserDoesntFullfillEndEntityProfile("Couldn't find hard token issuers among available hard token issuers.");
        }
      }
      
     // Check if ca id is among available ca ids.
      String[] availablecaids;
      try{
        availablecaids = getValue(AVAILCAS,0).split(SPLITCHAR);
      }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablecaids == null) {
          throw new UserDoesntFullfillEndEntityProfile("Error End Entity Profiles Available CAs is null.");
      }
      boolean caidfound=false;
      for(int i=0; i < availablecaids.length;i++){
          int tmp = Integer.parseInt(availablecaids[i]);
          if( tmp == caid || tmp == SecConst.ALLCAS) {
        	  caidfound=true;
          }
      }
      
      if(!caidfound) {
          throw new UserDoesntFullfillEndEntityProfile("Couldn't find CA ("+caid+") among End Entity Profiles Available CAs.");
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
	  Date now = new Date();
	  Date startTimeDate = null;
      if( getUse(STARTTIME, 0) && startTime != null && !startTime.equals("") ) {
    	  if ( startTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
    		  String[] startTimeArray = startTime.split(":");
    		  if ( Long.parseLong(startTimeArray[0]) < 0 || Long.parseLong(startTimeArray[1]) < 0 || Long.parseLong(startTimeArray[2]) < 0 ) {
    			  throw new UserDoesntFullfillEndEntityProfile("Cannot use negtive relative time.");
    		  }
    		  
    		  long relative = (Long.parseLong(startTimeArray[0])*24*60 + Long.parseLong(startTimeArray[1])*60 +
    				  Long.parseLong(startTimeArray[2])) * 60 * 1000;
    		  startTimeDate = new Date(now.getTime() + relative);
    	  } else {
    		  try {
    			  startTimeDate = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(startTime);
    		  } catch (ParseException e) {
    		  }
    	  }
    	  if (startTimeDate == null) {
    	      // If we could not parse the date string, something was awfully wrong
        	  throw new UserDoesntFullfillEndEntityProfile("Invalid start time: "+startTime);    		  
    	  }
      }
	  Date endTimeDate = null;
      if( getUse(ENDTIME, 0) && endTime != null && !endTime.equals("") ) {
    	  if ( endTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
    		  String[] endTimeArray = endTime.split(":");
    		  if ( Long.parseLong(endTimeArray[0]) < 0 || Long.parseLong(endTimeArray[1]) < 0 || Long.parseLong(endTimeArray[2]) < 0 ) {
    			  throw new UserDoesntFullfillEndEntityProfile("Cannot use negtive relative time.");
    		  }
    		  long relative = (Long.parseLong(endTimeArray[0])*24*60 + Long.parseLong(endTimeArray[1])*60 +
    				  Long.parseLong(endTimeArray[2])) * 60 * 1000;
    		  // If we haven't set a startTime, use "now"
    		  Date start = (startTimeDate == null) ? new Date(): startTimeDate;
    		  endTimeDate = new Date(start.getTime() + relative);
    	  } else {
    		  try {
    			  endTimeDate = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(endTime);
    		  } catch (ParseException e) {
    		  }
    	  }
    	  if (endTimeDate == null) {
    	      // If we could not parse the date string, something was awfulyl wrong
        	  throw new UserDoesntFullfillEndEntityProfile("Invalid end time: "+endTime);    		  
    	  }
      }
      if ( (startTimeDate != null) && (endTimeDate != null) ) {
    	  if ( getUse(STARTTIME, 0) && getUse(ENDTIME, 0) && !startTimeDate.before(endTimeDate) ) {
    		  throw new UserDoesntFullfillEndEntityProfile("Dates must be in right order. "+startTime+" "+endTime+" "+
    				  DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(startTimeDate) + " "+
    				  DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(endTimeDate));
    	  }    	  
      }
	  
      String allowedRequests = null;
      if ( ei != null ) {
    	  allowedRequests = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
      }
      if ( (allowedRequests != null) && !getUse(ALLOWEDREQUESTS, 0) ) {
    	  throw new UserDoesntFullfillEndEntityProfile("Allowed requests used, but not permitted by profile.");
      }

      String issuanceRevReason = null;
      if ( ei != null ) {
    	  issuanceRevReason = ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
      }
      if ( (issuanceRevReason != null) && !getUse(ISSUANCEREVOCATIONREASON, 0) ) {
    	  throw new UserDoesntFullfillEndEntityProfile("Issuance revocation reason used, but not permitted by profile.");
      }
      if ( getUse(ISSUANCEREVOCATIONREASON, 0) && !isModifyable(ISSUANCEREVOCATIONREASON, 0) ) {
    	  String value = getValue(ISSUANCEREVOCATIONREASON, 0);
    	  if (!StringUtils.equals(issuanceRevReason, value)) {
    		  throw new UserDoesntFullfillEndEntityProfile("Issuance revocation reason '"+issuanceRevReason+"' does not match required value '"+value+"'.");
    	  }
      }
      
      if ( getUse(MAXFAILEDLOGINS, 0) && !isModifyable(MAXFAILEDLOGINS,0)) {
    	  // If we MUST have MAXFAILEDLOGINS, ei can not be null
    	  if ( (ei == null) || !getValue(MAXFAILEDLOGINS,0).equals(Integer.toString(ei.getMaxLoginAttempts())) ) {
    		  throw new UserDoesntFullfillEndEntityProfile("Max failed logins is not modifyable.");
    	  }
      }      
  	if (log.isTraceEnabled()) {
  		log.trace("<doesUserFullfillEndEntityProfileWithoutPassword()");
  	}
    } // doesUserFullfillEndEntityProfileWithoutPassword
    
    /**
     * This function tries to match each field in the profile to a corresponding field in the DN/AN/AD-fields.
     * Can not be used for DNFieldExtractor.TYPE_SUBJECTDIRATTR yet.
     *   
     * @param fields
     * @param type One of DNFieldExtractor.TYPE_SUBJECTDN, DNFieldExtractor.TYPE_SUBJECTALTNAME
     * @param email The end entity's email address
     * @throws UserDoesntFullfillEndEntityProfile
     */
    private void checkIfFieldsMatch(DNFieldExtractor fields, int type, String email) throws UserDoesntFullfillEndEntityProfile {
    	final int REQUIRED_FIELD		= 2;
    	final int NONMODIFYABLE_FIELD	= 1;
    	final int MATCHED_FIELD			= -1;
    	Integer[] dnids = DNFieldExtractor.getUseFields(type);
    	// For each type of field
    	for ( int i=0; i<dnids.length; i++ ) {
    		int dnid = dnids[i].intValue();
    		int profileID = DnComponents.dnIdToProfileId(dnid);
    		int dnFieldExtractorID = DnComponents.profileIdToDnId(profileID);
    		int nof = fields.getNumberOfFields(dnFieldExtractorID);
    		int numberOfProfileFields = getNumberOfField(profileID);
    		if ( nof == 0 && numberOfProfileFields == 0 ) {
    			continue;	// Nothing to see here..
    		}
    		// Create array with all entries of that type
    		String[] subjectsToProcess = new String[nof];
    		for ( int j=0; j<nof; j++ ) {
    			String fieldValue = fields.getField(dnFieldExtractorID, j);
    			// Only keep domain for comparison of RFC822NAME, DNEMAIL and UPN fields
    			if ( DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.DNEMAIL.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.UPN.equals(DnComponents.dnIdToProfileName(dnid)) ) {
        			if ( fieldValue.indexOf('@') == -1 ) {
        				throw new UserDoesntFullfillEndEntityProfile(DnComponents.dnIdToProfileName(dnid) + " does not seem to be in something@somthingelse format.");
        			}
        			fieldValue = fieldValue.split("@")[1];
    			} else {
        			// Check that postalAddress has #der_encoding_in_hex format, i.e. a full der sequence in hex format
        			if ( DnComponents.POSTALADDRESS.equals(DnComponents.dnIdToProfileName(dnid))) {
        				if (!StringUtils.startsWith(fieldValue, "#30")) {
            				throw new UserDoesntFullfillEndEntityProfile(DnComponents.dnIdToProfileName(dnid) + " ("+fieldValue+") does not seem to be in #der_encoding_in_hex format. See \"http://ejbca.org/userguide.html#End Entity Profile fields\" for more information about the postalAddress (2.5.4.16) field.");        					
        				}
        			}    				
    			}
    			subjectsToProcess[j] = fieldValue;
    		}
    		//	Create array with profile values 3 = required and non-mod, 2 = required, 1 = non-modifiable, 0 = neither
    		int[] profileCrossOffList = new int[numberOfProfileFields];
    		for ( int j=0; j< getNumberOfField(profileID); j++ ) {
    			profileCrossOffList[j] += ( isModifyable(profileID, j) ? 0 : NONMODIFYABLE_FIELD ) + ( isRequired(profileID, j) ? REQUIRED_FIELD : 0 ); 
    		}
    		// Start by matching email strings
			if ( DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid)) || DnComponents.DNEMAIL.equals(DnComponents.dnIdToProfileName(dnid)) ) {
	    		for ( int k=3; k>=0; k--) {
	    			//	For every value in profile
	    			for ( int l=0; l<profileCrossOffList.length; l++ ) {
	    				if ( profileCrossOffList[l] == k ) {
	    					//	Match with every value in field-array
	    					for ( int m=0; m<subjectsToProcess.length; m++ ) {
	    						if ( subjectsToProcess[m] != null && profileCrossOffList[l] != MATCHED_FIELD ) {
	    							if ( !(!getUse(profileID, l) && DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid))) ) {
	    								if ( fields.getField(dnFieldExtractorID, m).equals(email) ){
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
    		// For every field of this type in profile (start with required and non-modifiable, 2 + 1)
    		for ( int k=3; k>=0; k--) {
    			// For every value in profile
    			for ( int l=0; l<profileCrossOffList.length; l++ ) {
    				if ( profileCrossOffList[l] == k ) {
    					// Match with every value in field-array
    					for ( int m=0; m<subjectsToProcess.length; m++ ) {
    						if ( subjectsToProcess[m] != null && profileCrossOffList[l] != MATCHED_FIELD ) {
        						// Match actual value if required + non-modifiable or non-modifiable
        						if ( (k == (REQUIRED_FIELD + NONMODIFYABLE_FIELD) || k == (NONMODIFYABLE_FIELD)) ) {
        							// Try to match with all possible values
        							String[] fixedValues = getValue(profileID, l).split(SPLITCHAR);
        							for ( int n=0; n<fixedValues.length; n++) {
        								if ( subjectsToProcess[m] != null && subjectsToProcess[m].equals(fixedValues[n]) ) {
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
    				throw new UserDoesntFullfillEndEntityProfile("End entity profile does not contain matching field for " +
    						DnComponents.dnIdToProfileName(dnid) + " with value \"" + subjectsToProcess[j] + "\".");
    			}
    		}
    		// If not all required fields in profile were found in subject 
    		for ( int j=0; j< getNumberOfField(profileID); j++ ) {
    			if ( profileCrossOffList[j] >= REQUIRED_FIELD ) {
    				throw new UserDoesntFullfillEndEntityProfile("Data does not contain required " + DnComponents.dnIdToProfileName(dnid) + " field.");
    			}
    		}
    	}
    } // checkIfFieldsMatch

	public void doesPasswordFulfillEndEntityProfile(String password, boolean clearpwd)
      throws UserDoesntFullfillEndEntityProfile{
    	
		boolean fullfillsprofile = true;
		if(useAutoGeneratedPasswd()){
			if(password !=null) {
				throw new UserDoesntFullfillEndEntityProfile("Autogenerated password must have password==null");
			}
		} else {           		            
			if(!isModifyable(EndEntityProfile.PASSWORD,0)){
				if(!password.equals(getValue(EndEntityProfile.PASSWORD,0))) {		   
					fullfillsprofile=false;
				}
			} else {
				if(isRequired(EndEntityProfile.PASSWORD,0)){
					if((!clearpwd && password == null) || (password != null && password.trim().equals(""))) {			
						fullfillsprofile=false;
					}
				}
			}
		}
           
		 if(clearpwd && isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) && getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.FALSE)){		 	
			 fullfillsprofile=false;
		 }
		 
		 if(!fullfillsprofile) {
		   throw new UserDoesntFullfillEndEntityProfile("Password doesn't fullfill profile.");
		 }
    }

    public Object clone() throws CloneNotSupportedException {
      EndEntityProfile clone = new EndEntityProfile();
      // We need to make a deep copy of the hashmap here
      HashMap clonedata = (HashMap) clone.saveData();
      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key,data.get(key));
      }
      clone.loadData(clonedata);
      return clone;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */
    public void upgrade() {
        log.trace(">upgrade");        
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			String msg = intres.getLocalizedMessage("ra.eeprofileupgrade", new Float(getVersion()));
            log.info(msg);
            // New version of the class, upgrade
            if(getVersion() < 1){
                ArrayList numberarray = (ArrayList)   data.get(NUMBERARRAY);
                while(numberarray.size() < 37){
                   numberarray.add(Integer.valueOf(0));
                }
                data.put(NUMBERARRAY,numberarray);
              }
            if(getVersion() < 2){
                ArrayList numberarray = (ArrayList)   data.get(NUMBERARRAY);
                while(numberarray.size() < 39){
                   numberarray.add(Integer.valueOf(0));
                }
                data.put(NUMBERARRAY,numberarray);
                
                addField(AVAILCAS);
                addField(DEFAULTCA);
                setRequired(AVAILCAS,0,true);
                setRequired(DEFAULTCA,0,true);
            }
            if(getVersion() < 3){
            	// These fields have been removed in version 8, no need for this upgrade
                //setNotificationSubject("");
                //setNotificationSender("");
                //setNotificationMessage("");
            }
            
            if(getVersion() < 4){
                ArrayList numberoffields = (ArrayList)   data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                  numberoffields.add(Integer.valueOf(0));
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
                ArrayList numberoffields = (ArrayList)   data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                  numberoffields.add(Integer.valueOf(0));
                }               
                data.put(NUMBERARRAY,numberoffields);
                data.put(SUBJECTDIRATTRFIELDORDER,new ArrayList());
                
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
                ArrayList numberoffields = (ArrayList) data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                	numberoffields.add(Integer.valueOf(0));
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
                ArrayList numberoffields = (ArrayList) data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                	numberoffields.add(Integer.valueOf(0));
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

            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.trace("<upgrade");
    }


    public static boolean isFieldImplemented(int field) {
    	String f = getParameter(field);
    	if (f == null) {
    		log.info("isFieldImplemented got call for non-implemented field: "+field);
    		return false;
    	}
    	return isFieldImplemented(f);
    }
    public static boolean isFieldImplemented(String field) {
    	boolean ret = true;
        if(field.equals(DnComponents.OTHERNAME) 
        		|| field.equals(DnComponents.X400ADDRESS) 
        		|| field.equals(DnComponents.EDIPARTNAME) 
        		|| field.equals(DnComponents.REGISTEREDID)) {
    		log.info("isFieldImplemented got call for non-implemented field: "+field);
        	ret = false;
        }
        return ret;
    }

	public static boolean isFieldOfType(int fieldNumber, String fieldString) {
		boolean ret = false;
		int number = getParameterNumber(fieldString);
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
     * 
     */
    private void checkIfDomainFullfillProfile(String field, int number, String nameAndDomain, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!nameAndDomain.trim().equals("") && nameAndDomain.indexOf('@') == -1) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + "(" + nameAndDomain + "). There must be a '@' character in the field.");
    	}
    	
    	String domain = nameAndDomain.substring(nameAndDomain.indexOf('@') + 1);

    	// All fields except RFC822NAME has to be empty if not used flag is set.
        if ( !DnComponents.RFC822NAME.equals(field) && !getUse(field,number) && !nameAndDomain.trim().equals("") ) {
            throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
        }
      
        if(!isModifyable(field,number) && !nameAndDomain.equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(domain.equals(values[i].trim())) {
              exists = true;
            }
          }
          if(!exists) {
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
          }
        }
    }
    
    private void checkForIllegalChars(String str) throws UserDoesntFullfillEndEntityProfile {
    	if (StringTools.hasSqlStripChars(str)) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + str + ". Contains illegal characters.");    		
    	}    	
    }
    /**
     * Used for iso 3166 country codes
     * 
     */
    private void checkIfISO3166FullfillProfile(String field, int number, String country, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!country.trim().equals("") && country.trim().length() != 2) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be of length two.");
    	}
    	
        if(!getUse(field,number) && !country.trim().equals("")) {
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
        }
      
        if(!isModifyable(field,number) && !country.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(country.equals(values[i].trim())) {
              exists = true;
            }
          }
          if(!exists) {
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
          }
        }
    }
    
    /**
     * Used to check if it is an M or an F
     * 
     */
    private void checkIfGenderFullfillProfile(String field, int number, String gender, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!gender.trim().equals("") && !(gender.equalsIgnoreCase("m") || gender.equalsIgnoreCase("f"))) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be M or F.");
    	}
    	
        if(!getUse(field,number) && !gender.trim().equals("")) {
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
        }
      
        if(!isModifyable(field,number) && !gender.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(gender.equals(values[i].trim())) {
              exists = true;
            }
          }
          if(!exists) {
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
          }
        }
    }

    /**
     * Used for date strings, should be YYYYMMDD
     * 
     */
    private void checkIfDateFullfillProfile(String field, int number, String date, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!date.trim().equals("") && date.trim().length() != 8) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be of length eight.");
    	}
    	if(!date.trim().equals("") && !StringUtils.isNumeric(date.trim())) {
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be only numbers.");
    	}
    	
        if(!getUse(field,number) && !date.trim().equals("")) {
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
        }
      
        if(!isModifyable(field,number) && !date.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(date.equals(values[i].trim())) {
              exists = true;
            }
          }
          if(!exists) {
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
          }
        }
    }
    
    /**
     * Verifies that non-modifiable data is available in profile.
     * @throws UserDoesntFullfillEndEntityProfile
     */
    private void checkIfDataFullfillProfile(String field, int number, String data, String text, String email) throws UserDoesntFullfillEndEntityProfile {

    	if(data == null && !field.equals(EMAIL)) {
    		throw new UserDoesntFullfillEndEntityProfile("Field " +  text + " cannot be null.");
    	}

    	if(data !=null) {
    		if(!getUse(field,number) && !data.trim().equals("")) {
    			throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
    		}
    	}

    	if(field.equals(DnComponents.DNEMAIL)){
    		if(isRequired(field,number)){
    			if(!data.trim().equals(email.trim())) {
    				throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match Email field.");
    			}
    		}
    	} else if( field.equals(DnComponents.RFC822NAME) && isRequired(field,number) && getUse(field,number) ) {
    		if(!data.trim().equals(email.trim())) {
    			throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match Email field.");
    		}
    	}
    	else{
    		if(!isModifyable(field,number)){
    			String[] values;
    			try{
    				values = getValue(field, number).split(SPLITCHAR);
    			}catch(Exception e){
    				throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
    			}
    			boolean exists = false;
    			for(int i = 0; i < values.length ; i++){
    				if(data.equals(values[i].trim())) {
    					exists = true;
    				}
    			}
    			if(!exists) {
    				throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
    			}
    		}
    	}
    }

    private void checkIfAllRequiredFieldsExists(DNFieldExtractor subjectdnfields, DNFieldExtractor subjectaltnames, DNFieldExtractor subjectdirattrs, String username, String email)  throws UserDoesntFullfillEndEntityProfile{
        int size;

        // Check if Username exists.
        if(isRequired(USERNAME,0)){
          if(username == null || username.trim().equals("")) {
            throw new UserDoesntFullfillEndEntityProfile("Username cannot be empty or null.");
          }
        }

        // Check if required Email fields exists.
        if(isRequired(EMAIL,0)){
          if(email == null || email.trim().equals("")) {
            throw new UserDoesntFullfillEndEntityProfile("Email address cannot be empty or null.");
          }
        }


        // Check if all required subjectdn fields exists.
        String[] dnfields = getSubjectDNProfileFields();
        Integer[] dnFieldExtractorIds = (Integer[])DnComponents.getDnDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dnfields.length; i++){
        	if(getReverseFieldChecks()){
        		int nof = subjectdnfields.getNumberOfFields(dnFieldExtractorIds[i].intValue());
        	    int numRequiredFields = getNumberOfRequiredFields(dnfields[i]);
        	    if(nof < numRequiredFields){
        	      throw new UserDoesntFullfillEndEntityProfile("Subject DN field '" + dnfields[i] + "' must exist.");
        	    }
        	}else{
               size = getNumberOfField(dnfields[i]);
               for(int j = 0; j < size; j++){
            	   if(isRequired(dnfields[i],j)) {
            		   if(subjectdnfields.getField(dnFieldExtractorIds[i].intValue(),j).trim().equals("")) {
            			   throw new UserDoesntFullfillEndEntityProfile("Subject DN field '" + dnfields[i] + "' must exist.");
            		   }
            	   }
               }
            }
        }
        
        

         // Check if all required subject alternate name fields exists.
        String[] altnamefields = getSubjectAltnameProfileFields();
        Integer[] altNameFieldExtractorIds = (Integer[])DnComponents.getAltNameDnIds().toArray(new Integer[0]);
        for(int i = 0; i < altnamefields.length; i++){
        	if(getReverseFieldChecks()){
        		int nof = subjectaltnames.getNumberOfFields(altNameFieldExtractorIds[i].intValue());
        		int numRequiredFields = getNumberOfRequiredFields(altnamefields[i]);
        		if(nof < numRequiredFields){
        			throw new UserDoesntFullfillEndEntityProfile("Subject Alternative Name field '" + altnamefields[i] + "' must exist.");
        		}
        	}else{
        		// Only verify fields that are actually used
        		// size = getNumberOfField(altnamefields[i]);
        		size = subjectaltnames.getNumberOfFields(altNameFieldExtractorIds[i].intValue());
        		for(int j = 0; j < size; j++){
        			if(isRequired(altnamefields[i],j)) {
        				if(subjectaltnames.getField(altNameFieldExtractorIds[i].intValue(),j).trim().equals("")) {
        					throw new UserDoesntFullfillEndEntityProfile("Subject Alterntive Name field '" + altnamefields[i] + "' must exist.");
        				}
        			}
        		}
        	}
        }

        // Check if all required subject directory attribute fields exists.
        String[] dirattrfields = getSubjectDirAttrProfileFields();
        Integer[] dirAttrFieldExtractorIds = (Integer[])DnComponents.getDirAttrDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dirattrfields.length; i++){        	
        	size = getNumberOfField(dirattrfields[i]);
        	for(int j = 0; j < size; j++){
        		if(isRequired(dirattrfields[i],j)) {
        			if(subjectdirattrs.getField(dirAttrFieldExtractorIds[i].intValue(),j).trim().equals("")) {
        				throw new UserDoesntFullfillEndEntityProfile("Subject Directory Attribute field '" + dirattrfields[i] + "' must exist.");
        			}
        		}
        	}
        }

    }

  /**
   * Method calculating the number of required fields of on kind that is configured for this profile.
   * @param field, one of the field constants
   * @return The number of required fields of that kind.
   */
    private int getNumberOfRequiredFields(String field) {
    	int retval = 0;
    	int size = getNumberOfField(field);
    	for(int j = 0; j < size; j++){
    		if(isRequired(field,j)){
    			retval++;
    		}
    	}   	
    	
    	return retval;
    }

	private void  checkIfForIllegalNumberOfFields(DNFieldExtractor subjectdnfields, DNFieldExtractor subjectaltnames, DNFieldExtractor subjectdirattrs) throws UserDoesntFullfillEndEntityProfile{

        // Check number of subjectdn fields.
        String[] dnfields = getSubjectDNProfileFields();
        Integer[] dnFieldExtractorIds = (Integer[])DnComponents.getDnDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dnfields.length; i++){
            if(getNumberOfField(dnfields[i]) < subjectdnfields.getNumberOfFields(dnFieldExtractorIds[i].intValue())) {
              throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + dnfields[i] + " fields in Subject DN.");
            }
        }

         // Check number of subject alternate name fields.
        String[] altnamefields = getSubjectAltnameProfileFields();
        Integer[] altNameFieldExtractorIds = (Integer[])DnComponents.getAltNameDnIds().toArray(new Integer[0]);
        for(int i = 0; i < altnamefields.length; i++){
          if(getNumberOfField(altnamefields[i]) < subjectaltnames.getNumberOfFields(altNameFieldExtractorIds[i].intValue())) {
           throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + altnamefields[i] + " fields in Subject Alternative Name.");
          }
        }

        // Check number of subject directory attribute fields.
        String[] dirattrfields = getSubjectDirAttrProfileFields();
        Integer[] dirAttrFieldExtractorIds = (Integer[])DnComponents.getDirAttrDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dirattrfields.length; i++){
          if(getNumberOfField(dirattrfields[i]) < subjectdirattrs.getNumberOfFields(dirAttrFieldExtractorIds[i].intValue())) {
           throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + dirattrfields[i] + " fields in Subject Directory Attributes.");
          }
        }
    }

	/** methods for mapping the DN, AltName, DirAttr constants from string->number
	 * 
	 */
	private static int getParameterNumber(String parameter) {
		Integer number = (Integer)dataConstants.get(parameter);
		if (number != null) {
			return number.intValue();			
		}
		log.error("No parameter number for "+parameter);
		return -1;
	}
	/** methods for mapping the DN, AltName, DirAttr constants from number->string
	 * 
	 */
	private static String getParameter(int parameterNumber) {
		Set set = dataConstants.entrySet();
		Iterator iter = set.iterator();
		String ret = null;
		while (iter.hasNext() && ret == null) {
			Map.Entry entry = (Map.Entry)iter.next();
			Integer val = (Integer)entry.getValue();
			if (val.intValue() == parameterNumber) {
				ret = (String)entry.getKey();
			}
		}
		if (ret == null) {
			log.error("No parameter for "+parameterNumber);			
		}
		return ret;
	}
	
    private void  incrementFieldnumber(int parameter){
      ArrayList numberarray = (ArrayList) data.get(NUMBERARRAY);
      numberarray.set(parameter, Integer.valueOf(((Integer) numberarray.get(parameter)).intValue() + 1));
    }

    private void  decrementFieldnumber(int parameter){
      ArrayList numberarray = (ArrayList) data.get(NUMBERARRAY);
      numberarray.set(parameter, Integer.valueOf(((Integer) numberarray.get(parameter)).intValue() - 1));
    }
    


    // Private Constants.
    private static final int FIELDBOUNDRARY  = 10000;
    private static final int NUMBERBOUNDRARY = 100;

    
    public static String[] getSubjectDNProfileFields() {
    	return (String[])DnComponents.getDnProfileFields().toArray(new String[0]);
    }

    public static String[] getSubjectAltnameProfileFields() {
    	return (String[])DnComponents.getAltNameFields().toArray(new String[0]);
    }

    public static String[] getSubjectDirAttrProfileFields() {
    	return (String[])DnComponents.getDirAttrFields().toArray(new String[0]);
    }


    /** Number array keeps track of how many fields there are of a specific type, for example 2 OranizationUnits, 0 TelephoneNumber */
    private static final String NUMBERARRAY               = "NUMBERARRAY";
    private static final String SUBJECTDNFIELDORDER       = "SUBJECTDNFIELDORDER";
    private static final String SUBJECTALTNAMEFIELDORDER  = "SUBJECTALTNAMEFIELDORDER";
    private static final String SUBJECTDIRATTRFIELDORDER  = "SUBJECTDIRATTRFIELDORDER";
    
    private static final String USERNOTIFICATIONS         = "USERNOTIFICATIONS";

    private static final String REUSECERTIFICATE = "REUSECERTIFICATE";
    private static final String REVERSEFFIELDCHECKS = "REVERSEFFIELDCHECKS"; 
    private static final String ALLOW_MERGEDN_WEBSERVICES = "ALLOW_MERGEDN_WEBSERVICES";
    
    private static final String PRINTINGUSE            = "PRINTINGUSE";
    private static final String PRINTINGDEFAULT        = "PRINTINGDEFAULT";
    private static final String PRINTINGREQUIRED       = "PRINTINGREQUIRED";
    private static final String PRINTINGCOPIES         = "PRINTINGCOPIES";
    private static final String PRINTINGPRINTERNAME    = "PRINTINGPRINTERNAME";
    private static final String PRINTINGSVGFILENAME    = "PRINTINGSVGFILENAME";
    private static final String PRINTINGSVGDATA        = "PRINTINGSVGDATA";
    // Private fields.


}
