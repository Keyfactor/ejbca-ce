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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.UpgradeableDataHashMap;
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
 * @version $Id: EndEntityProfile.java,v 1.13 2006-12-04 10:09:34 anatom Exp $
 */
public class EndEntityProfile extends UpgradeableDataHashMap implements java.io.Serializable, Cloneable {

    private static Logger log = Logger.getLogger(EndEntityProfile.class);
    public static final float LATEST_VERSION = 6;

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8356152324295231461L;
    
    // Public constants
    /** Constant values for end entity profile. */
    private static HashMap dataConstants = new HashMap();

    // Default values
    // These must be in a strict order that can never change 
    // Custom values configurable in a properties file will start at number 100
    static {
    	dataConstants.put("USERNAME", Integer.valueOf(0));
    	dataConstants.put("PASSWORD", Integer.valueOf(1));
    	dataConstants.put("CLEARTEXTPASSWORD", Integer.valueOf(2));
        // DN components
    	/* These are loaded through DnComponents instead
    	dataConstants.put(DnComponents.DNEMAIL, Integer.valueOf(3));
    	dataConstants.put(DnComponents.UID, Integer.valueOf(4));
    	dataConstants.put(DnComponents.COMMONNAME, Integer.valueOf(5));
    	dataConstants.put(DnComponents.SN, Integer.valueOf(6));
    	dataConstants.put(DnComponents.GIVENNAME, Integer.valueOf(7));
    	dataConstants.put(DnComponents.INITIALS, Integer.valueOf(8));
    	dataConstants.put(DnComponents.SURNAME, Integer.valueOf(9));
    	dataConstants.put(DnComponents.TITLE, Integer.valueOf(10));
    	dataConstants.put(DnComponents.ORGANIZATIONUNIT, Integer.valueOf(11));
    	dataConstants.put(DnComponents.ORGANIZATION, Integer.valueOf(12));
    	dataConstants.put(DnComponents.LOCALE, Integer.valueOf(13));
    	dataConstants.put(DnComponents.STATE, Integer.valueOf(14));
    	dataConstants.put(DnComponents.DOMAINCOMPONENT, Integer.valueOf(15));
    	dataConstants.put(DnComponents.COUNTRY, Integer.valueOf(16));

    	dataConstants.put(DnComponents.UNSTRUCTUREDADDRESS, Integer.valueOf(39));
    	dataConstants.put(DnComponents.UNSTRUCTUREDNAME, Integer.valueOf(40));
        // AltNames
    	dataConstants.put(DnComponents.RFC822NAME, Integer.valueOf(17));
    	dataConstants.put(DnComponents.DNSNAME, Integer.valueOf(18));
    	dataConstants.put(DnComponents.IPADDRESS, Integer.valueOf(19));
    	dataConstants.put(DnComponents.OTHERNAME, Integer.valueOf(20));
    	dataConstants.put(DnComponents.UNIFORMRESOURCEID, Integer.valueOf(21));
    	dataConstants.put(DnComponents.X400ADDRESS, Integer.valueOf(22));
    	dataConstants.put(DnComponents.DIRECTORYNAME, Integer.valueOf(23));
    	dataConstants.put(DnComponents.EDIPARTNAME, Integer.valueOf(24));
    	dataConstants.put(DnComponents.REGISTEREDID, Integer.valueOf(25));

    	dataConstants.put(DnComponents.UPN, Integer.valueOf(36));

    	dataConstants.put(DnComponents.GUID, Integer.valueOf(41));
    	// Altnames end
        // Subject directory attributes
    	dataConstants.put(DnComponents.DATEOFBIRTH, Integer.valueOf(42));
    	dataConstants.put(DnComponents.PLACEOFBIRTH, Integer.valueOf(43));
    	dataConstants.put(DnComponents.GENDER, Integer.valueOf(44));
    	dataConstants.put(DnComponents.COUNTRYOFCITIZENSHIP, Integer.valueOf(45));
    	dataConstants.put(DnComponents.COUNTRYOFRESIDENCE, Integer.valueOf(46));
        // Subject directory attributes end
    	 */
    	dataConstants.put("EMAIL", Integer.valueOf(26));
    	dataConstants.put("ADMINISTRATOR", Integer.valueOf(27));
    	dataConstants.put("KEYRECOVERABLE", Integer.valueOf(28));
    	dataConstants.put("DEFAULTCERTPROFILE", Integer.valueOf(29));
    	dataConstants.put("AVAILCERTPROFILES", Integer.valueOf(30));
    	dataConstants.put("DEFKEYSTORE", Integer.valueOf(31));
    	dataConstants.put("AVAILKEYSTORE", Integer.valueOf(32));
    	dataConstants.put("DEFAULTTOKENISSUER", Integer.valueOf(33));
    	dataConstants.put("AVAILTOKENISSUER", Integer.valueOf(34));
    	dataConstants.put("SENDNOTIFICATION", Integer.valueOf(35));

    	dataConstants.put("DEFAULTCA", Integer.valueOf(37));
    	dataConstants.put("AVAILCAS", Integer.valueOf(38));
    	
    	// Load all DN, altName and directoryAttributes from DnComponents.
    	dataConstants.putAll(DnComponents.getProfilenameIdMap());
    }
    // Type of data constants.
    private static final int VALUE      = 0;
    private static final int USE        = 1;
    private static final int ISREQUIRED = 2;
    private static final int MODIFYABLE = 3;

    // Field constants, used in the map above
    public static final String USERNAME           = "USERNAME";
    public static final String PASSWORD           = "PASSWORD";
    public static final String CLEARTEXTPASSWORD  = "CLEARTEXTPASSWORD";
    
    public static final String EMAIL              = "EMAIL";
    public static final String ADMINISTRATOR      = "ADMINISTRATOR";
    public static final String KEYRECOVERABLE     = "KEYRECOVERABLE";
    public static final String DEFAULTCERTPROFILE = "DEFAULTCERTPROFILE";
    public static final String AVAILCERTPROFILES  = "AVAILCERTPROFILES";
    public static final String DEFKEYSTORE        = "DEFKEYSTORE";
    public static final String AVAILKEYSTORE      = "AVAILKEYSTORE";
    public static final String DEFAULTTOKENISSUER = "DEFAULTTOKENISSUER";
    public static final String AVAILTOKENISSUER   = "AVAILTOKENISSUER";
    public static final String SENDNOTIFICATION   = "SENDNOTIFICATION";
    public static final String DEFAULTCA          = "DEFAULTCA";
    public static final String AVAILCAS           = "AVAILCAS";
    
    

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
      if(emptyprofile){
        // initialize profile data
        ArrayList numberoffields = new ArrayList(dataConstants.size());
        for(int i =0; i < dataConstants.size(); i++){
          numberoffields.add(new Integer(0));
        }
        data.put(NUMBERARRAY,numberoffields);
        data.put(SUBJECTDNFIELDORDER,new ArrayList());
        data.put(SUBJECTALTNAMEFIELDORDER,new ArrayList());
        data.put(SUBJECTDIRATTRFIELDORDER,new ArrayList());

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

        setRequired(USERNAME,0,true);
        setRequired(PASSWORD,0,true);
        setRequired(DnComponents.COMMONNAME,0,true);
        setRequired(DEFAULTCERTPROFILE,0,true);
        setRequired(AVAILCERTPROFILES,0,true);
        setRequired(DEFKEYSTORE,0,true);
        setRequired(AVAILKEYSTORE,0,true);
        setRequired(DEFAULTCA,0,true);
        setRequired(AVAILCAS,0,true);
        setValue(DEFAULTCERTPROFILE,0,"1");
        setValue(AVAILCERTPROFILES,0,"1");
        setValue(DEFKEYSTORE,0, "" + SecConst.TOKEN_SOFT_BROWSERGEN);
        setValue(AVAILKEYSTORE,0, SecConst.TOKEN_SOFT_BROWSERGEN + ";" + SecConst.TOKEN_SOFT_P12 +  ";" + SecConst.TOKEN_SOFT_JKS + ";" + SecConst.TOKEN_SOFT_PEM);
        setValue(AVAILCAS,0, Integer.toString(SecConst.ALLCAS));
        // Do not use hard token issuers by default.
        setUse(AVAILTOKENISSUER, 0, false);

      }else{
         // initialize profile data
         ArrayList numberoffields = new ArrayList(dataConstants.size());
         for(int i =0; i < dataConstants.size(); i++){
           numberoffields.add(new Integer(0));
         }

         data.put(NUMBERARRAY,numberoffields);
         data.put(SUBJECTDNFIELDORDER,new ArrayList());
         data.put(SUBJECTALTNAMEFIELDORDER,new ArrayList());
         data.put(SUBJECTDIRATTRFIELDORDER,new ArrayList());

         addField(USERNAME);
         addField(PASSWORD);
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
         
         setRequired(USERNAME,0,true);
         setRequired(PASSWORD,0,true);
         setRequired(DnComponents.COMMONNAME,0,true);
         setRequired(DEFAULTCERTPROFILE,0,true);
         setRequired(AVAILCERTPROFILES,0,true);
         setRequired(DEFKEYSTORE,0,true);
         setRequired(AVAILKEYSTORE,0,true);
         setRequired(DEFAULTCA,0,true);
         setRequired(AVAILCAS,0,true);
         
         setValue(DEFAULTCERTPROFILE,0,"1");
         setValue(AVAILCERTPROFILES,0,"1;2;3");
         setValue(DEFKEYSTORE,0, "" + SecConst.TOKEN_SOFT_BROWSERGEN);
         setValue(AVAILKEYSTORE,0, SecConst.TOKEN_SOFT_BROWSERGEN + ";" + SecConst.TOKEN_SOFT_P12 +  ";" + SecConst.TOKEN_SOFT_JKS + ";" + SecConst.TOKEN_SOFT_PEM);

         // Do not use hard token issuers by default.
         setUse(AVAILTOKENISSUER, 0, false);

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
        fieldorder.add(new Integer((NUMBERBOUNDRARY*parameter) + size));
        Collections.sort(fieldorder);
      }
      ArrayList altNames = DnComponents.getAltNameFields();
      if(altNames.contains(param)) {
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
        fieldorder.add(new Integer((NUMBERBOUNDRARY*parameter) + size));
      }
      ArrayList dirAttrs = DnComponents.getDirAttrFields();
      if(dirAttrs.contains(param)){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
          fieldorder.add(new Integer((NUMBERBOUNDRARY*parameter) + size));
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
      // Remove field and move all fileds above.
      int size =  getNumberOfField(parameter);

      if(size>0){
        for(int n = number; n < size-1; n++){
          setValue(parameter,n,getValue(parameter,n+1));
          setRequired(parameter,n,isRequired(parameter,n+1));
          setUse(parameter,n,getUse(parameter,n+1));
          setModifyable(parameter,n,isModifyable(parameter,n+1));
        }

        String param = getParameter(parameter);
        // Remove from order list.
        ArrayList dns = DnComponents.getDnProfileFields();
        if(dns.contains(param)){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
          int value = (NUMBERBOUNDRARY*parameter) + number;
          for(int i=0; i < fieldorder.size(); i++){
             if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                fieldorder.remove(i);
                break;
             }
          }
        }

        ArrayList altNames = DnComponents.getAltNameFields();
        if(altNames.contains(param)) {
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
          int value = (NUMBERBOUNDRARY*parameter) + number;
          for(int i=0; i < fieldorder.size(); i++){
             if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                fieldorder.remove(i);
                break;
             }
          }
        }

        ArrayList dirAttrs = DnComponents.getDirAttrFields();
        if(dirAttrs.contains(param)){
            ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
            int value = (NUMBERBOUNDRARY*parameter) + number;
            for(int i=0; i < fieldorder.size(); i++){
               if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                  fieldorder.remove(i);
                  break;
               }
            }
          }

        data.remove(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        data.remove(new Integer((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        data.remove(new Integer((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        data.remove(new Integer((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));

        decrementFieldnumber(parameter);
      }
    }

    /**
     * Function that returns the number of one kind of field.
     *
     */
    public int getNumberOfField(String parameter){
    	return getNumberOfField(getParameterNumber(parameter));
    }
    public int getNumberOfField(int parameter){
    	ArrayList arr = (ArrayList)data.get(NUMBERARRAY);
    	// This is an automatic upgrade function, if we have dynamically added new fields
    	if (parameter >= arr.size()) {
    		log.info("Adding new field, "+parameter+", to NUMBERARRAY");
    		for (int i = arr.size(); i <= parameter; i++) {
                arr.add(new Integer(0));
    		}
            data.put(NUMBERARRAY,arr);
    	}
    	return ((Integer) arr.get(parameter)).intValue();
    }

    public void setValue(int parameter, int number, String value) {
        if(value !=null){
            value=value.trim();
            data.put(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), value);
         }else{
            data.put(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), "");
         }
    }
    public void setValue(String parameter, int number, String value) {
    	setValue(getParameterNumber(parameter), number, value);
    }

    public void setUse(int parameter, int number, boolean use){
          data.put(new Integer((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(use));
    }
    public void setUse(String parameter, int number, boolean use){
    	setUse(getParameterNumber(parameter), number, use);
    }

    public void setRequired(int parameter, int number,  boolean isrequired) {
    	data.put(new Integer((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(isrequired));
    }
    public void setRequired(String parameter, int number,  boolean isrequired) {
    	setRequired(getParameterNumber(parameter), number, isrequired);
    }

    public void setModifyable(int parameter, int number, boolean changeable) {
    	data.put(new Integer((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(changeable));
    }
    public void setModifyable(String parameter, int number, boolean changeable) {
    	setModifyable(getParameterNumber(parameter), number, changeable);
    }

    public String getValue(int parameter, int number) {
        String returnval = (String) data.get(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null)
            return returnval;
        return "";
    }
    public String getValue(String parameter, int number) {
    	return getValue(getParameterNumber(parameter), number);
    }

    public boolean getUse(int parameter, int number){
        Boolean returnval = (Boolean) data.get(new Integer((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null)
            return returnval.booleanValue();
        return false;
    }
    public boolean getUse(String parameter, int number){
    	return getUse(getParameterNumber(parameter), number);
    }

    public boolean isRequired(int parameter, int number) {
        Boolean returnval = (Boolean) data.get(new Integer((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null)
            return returnval.booleanValue();
        return false;
    }
    public boolean isRequired(String parameter, int number) {
    	return isRequired(getParameterNumber(parameter), number);
    }

    public boolean isModifyable(int parameter, int number){
        Boolean returnval = (Boolean) data.get(new Integer((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
        if(returnval != null)
            return returnval.booleanValue();
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
      returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % NUMBERBOUNDRARY;
      returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / NUMBERBOUNDRARY;

      return returnval;
    }

    public int[] getSubjectDirAttrFieldsInOrder(int index){
        int[] returnval = new int[2];
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTDIRATTRFIELDORDER);
        returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % NUMBERBOUNDRARY;
        returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / NUMBERBOUNDRARY;

        return returnval;
      }

    public Collection getAvailableCAs(){
        ArrayList availablecaids = new ArrayList();
        availablecaids.addAll(Arrays.asList(getValue(AVAILCAS,0).split(SPLITCHAR)));
        return availablecaids;
    }
    
    public boolean useAutoGeneratedPasswd(){    	
    	return !this.getUse(EndEntityProfile.PASSWORD,0);
    }
    
    public String getAutoGeneratedPasswd(){
    	return PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS).getNewPassword(6,8);    	
    }
    
    public String getNotificationSender(){
    	if(data.get(NOTIFICATIONSENDER) == null)
    		return "";
    	
    	return (String) data.get(NOTIFICATIONSENDER);
    }
    
    public void setNotificationSender(String sender){
    	data.put(NOTIFICATIONSENDER, sender);
    }
    
    public String getNotificationSubject(){
    	if(data.get(NOTIFICATIONSUBJECT) == null)
    		return "";
    	
    	return (String) data.get(NOTIFICATIONSUBJECT);
    }
    
    public void setNotificationSubject(String subject){
    	data.put(NOTIFICATIONSUBJECT, subject);
    }
        
    public String getNotificationMessage(){
    	if(data.get(NOTIFICATIONMESSAGE) == null)
    		return "";
    	    	
    	return (String) data.get(NOTIFICATIONMESSAGE);
    }
    
    public void setNotificationMessage(String message){
    	data.put(NOTIFICATIONMESSAGE, message);
    }
    
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
    	data.put(PRINTINGCOPIES, new Integer(copies));
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
    
    
        
    
    public void doesUserFullfillEndEntityProfile(String username, String password, String dn, String subjectaltname, String subjectdirattr, String email,  int certificateprofileid,
                                                 boolean clearpwd, boolean administrator, boolean keyrecoverable, boolean sendnotification,
                                                 int tokentype, int hardwaretokenissuerid, int caid)
       throws UserDoesntFullfillEndEntityProfile{

     if(useAutoGeneratedPasswd()){
	   if(password !=null)
		throw new UserDoesntFullfillEndEntityProfile("Autogenerated password must have password==null");
	 }else{  
        if(!isModifyable(PASSWORD,0)){
          if(!password.equals(getValue(PASSWORD,0)))
            throw new UserDoesntFullfillEndEntityProfile("Password didn't match requirement of it's profile.");
        }
        else
          if(isRequired(PASSWORD,0)){
            if(password == null || password.trim().equals(""))
              throw new UserDoesntFullfillEndEntityProfile("Password cannot be empty or null.");
          }
     }
     
      if(!getUse(CLEARTEXTPASSWORD,0) && clearpwd)
          throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be used.");

      if(isRequired(CLEARTEXTPASSWORD,0)){
        if(getValue(CLEARTEXTPASSWORD,0).equals(TRUE) && !clearpwd)
           throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be false.");
        if(getValue(CLEARTEXTPASSWORD,0).equals(FALSE) && clearpwd)
           throw new UserDoesntFullfillEndEntityProfile("Clearpassword (used in batch proccessing) cannot be true.");
      }

      doesUserFullfillEndEntityProfileWithoutPassword(username, dn, subjectaltname, subjectdirattr, email,  certificateprofileid, administrator, keyrecoverable, sendnotification, tokentype, hardwaretokenissuerid, caid);

    }

    public void doesUserFullfillEndEntityProfileWithoutPassword(String username,  String dn, String subjectaltname, String subjectdirattr, String email,  int certificateprofileid,
                                                                boolean administrator, boolean keyrecoverable, boolean sendnotification,
                                                                int tokentype, int hardwaretokenissuerid, int caid) throws UserDoesntFullfillEndEntityProfile{
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
      if(subjectdnfields.existsOther())
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject DN Field found in:" + dn);

      if(subjectaltnames.existsOther())
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject Alternate Name Field found in:" + subjectaltname );

      if(subjectdirattrs.existsOther())
          throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject Directory Attribute Field found in:" + subjectdirattr );

      checkIfAllRequiredFieldsExists(subjectdnfields, subjectaltnames, subjectdirattrs, username, email);

      checkIfForIllegalNumberOfFields(subjectdnfields, subjectaltnames, subjectdirattrs);

      // Check contents of username.
      checkIfDataFullfillProfile(USERNAME,0,username, "Username",null);

      //  Check Email address.
     if(email == null)
       email = "";
     checkIfDomainFullfillProfile(EMAIL,0,email,"Email");

      // Check contents of Subject DN fields.
      HashMap subjectdnfieldnumbers = subjectdnfields.getNumberOfFields();
      Integer[] dnids = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
      for(int i = 0; i < dnids.length; i++){
    	  Integer dnid = dnids[i];
		  int nof = ((Integer)subjectdnfieldnumbers.get(dnid)).intValue();
    	  if(getReverseFieldChecks()){
    		  for(int j=getNumberOfField(DnComponents.dnIdToProfileName(dnid.intValue())) -1; j >= 0; j--){    			 
    			  checkIfDataFullfillProfile(DnComponents.dnIdToProfileName(dnid.intValue()),j,subjectdnfields.getField(dnid.intValue(),--nof), DnComponents.getErrTextFromDnId(dnid.intValue()), email);
    		  }   		
    	  }else{
    		  for(int j=0; j < nof; j++){
    			  checkIfDataFullfillProfile(DnComponents.dnIdToProfileName(dnid.intValue()),j,subjectdnfields.getField(dnid.intValue(),j), DnComponents.getErrTextFromDnId(dnid.intValue()), email);
    		  }
    	  }
      }
       // Check contents of Subject Alternative Name fields.
      HashMap subjectaltnamesnumbers = subjectaltnames.getNumberOfFields();
      Integer[] altnameids = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTALTNAME);
      for(int i = 0; i < altnameids.length; i++){
    	  Integer altnameid = altnameids[i];
		  int nof = ((Integer)subjectaltnamesnumbers.get(altnameid)).intValue();
    	  if(getReverseFieldChecks()){
    		  for(int j=getNumberOfField(DnComponents.dnIdToProfileName(altnameid.intValue())) -1; j >= 0; j--){
    			  if(i == DNFieldExtractor.UPN){
    				  checkIfDomainFullfillProfile(DnComponents.UPN,j,subjectaltnames.getField(altnameid.intValue(),--nof),"UPN");
    			  }else{
    				  checkIfDataFullfillProfile(DnComponents.dnIdToProfileName(altnameid.intValue()),j,subjectaltnames.getField(altnameid.intValue(),--nof), DnComponents.getErrTextFromDnId(altnameid.intValue()), email);
    			  }   
    		  }    		      		  
    	  }else{
    		  for(int j=0; j < nof; j++){
    			  if(altnameid.intValue() == DNFieldExtractor.UPN){
    				  checkIfDomainFullfillProfile(DnComponents.UPN,j,subjectaltnames.getField(altnameid.intValue(),j),"UPN");
    			  }else{
    				  checkIfDataFullfillProfile(DnComponents.dnIdToProfileName(altnameid.intValue()),j,subjectaltnames.getField(altnameid.intValue(),j), DnComponents.getErrTextFromDnId(altnameid.intValue()), email);
    			  }   
    		  }
    	  }
      }

      // Check contents of Subject Directory Attributes fields.
      HashMap subjectdirattrnumbers = subjectdirattrs.getNumberOfFields();
      Integer[] dirattrids = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDIRATTR);
      for(int i = 0; i < dirattrids.length; i++){
    	  Integer dirattrid = dirattrids[i];
		  int nof = ((Integer)subjectdirattrnumbers.get(dirattrid)).intValue();
    	  for(int j=0; j < nof; j++){
    		  checkForIllegalChars(subjectdirattrs.getField(dirattrid.intValue(),j));
    		  if(i == DNFieldExtractor.COUNTRYOFCITIZENSHIP){
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

   // Check for administrator flag.
      if(!getUse(ADMINISTRATOR,0) &&  administrator)
          throw new UserDoesntFullfillEndEntityProfile("Administrator cannot be set.");

      if(isRequired(ADMINISTRATOR,0)){
        if(getValue(ADMINISTRATOR,0).equals(TRUE) && !administrator)
           throw new UserDoesntFullfillEndEntityProfile("Administrator flag is required.");
        if(getValue(ADMINISTRATOR,0).equals(FALSE) && administrator)
           throw new UserDoesntFullfillEndEntityProfile("Administrator flag cannot be set in current end entity profile.");
      }
   // Check for keyrecoverable flag.
      if(!getUse(KEYRECOVERABLE,0) &&  keyrecoverable)
          throw new UserDoesntFullfillEndEntityProfile("Key Recoverable cannot be used.");

      if(isRequired(KEYRECOVERABLE,0)){
        if(getValue(KEYRECOVERABLE,0).equals(TRUE) && !keyrecoverable)
           throw new UserDoesntFullfillEndEntityProfile("Key Recoverable is required.");
        if(getValue(KEYRECOVERABLE,0).equals(FALSE) && keyrecoverable)
           throw new UserDoesntFullfillEndEntityProfile("Key Recoverable cannot be set in current end entity profile.");
      }

   // Check for send notification flag.
      if(!getUse(SENDNOTIFICATION,0) &&  sendnotification)
          throw new UserDoesntFullfillEndEntityProfile("Email notification cannot be used.");

      if(isRequired(SENDNOTIFICATION,0)){
        if(getValue(SENDNOTIFICATION,0).equals(TRUE) && !sendnotification)
           throw new UserDoesntFullfillEndEntityProfile("Email notification is required.");
        if(getValue(SENDNOTIFICATION,0).equals(FALSE) && sendnotification)
           throw new UserDoesntFullfillEndEntityProfile("Email notification cannot be set in current end entity profile.");
      }

      // Check if certificate profile is among available certificate profiles.
      String[] availablecertprofiles;
      try{
        availablecertprofiles = getValue(AVAILCERTPROFILES,0).split(SPLITCHAR);
      }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablecertprofiles == null)
           throw new UserDoesntFullfillEndEntityProfile("Error Available certificate profiles is null.");
      boolean found=false;
      for(int i=0; i < availablecertprofiles.length;i++){
          if( Integer.parseInt(availablecertprofiles[i]) == certificateprofileid)
              found=true;
      }
      
      if(!found)
          throw new UserDoesntFullfillEndEntityProfile("Couldn't find certificate profile ("+certificateprofileid+") among available certificate profiles.");

      // Check if tokentype is among available  token types.
      String[] availablesofttokentypes;
      try{
        availablesofttokentypes = getValue(AVAILKEYSTORE,0).split(SPLITCHAR);
      }catch(Exception e){
        throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablesofttokentypes == null)
          throw new UserDoesntFullfillEndEntityProfile("Error available  token types is null.");
      found=false;
      for(int i=0; i < availablesofttokentypes.length;i++){
          if( Integer.parseInt(availablesofttokentypes[i]) == tokentype)
              found=true;
      }

      // If soft token check for hardwaretoken issuer id = 0.
      if(tokentype <= SecConst.TOKEN_SOFT){
        if(hardwaretokenissuerid != 0)
           throw new UserDoesntFullfillEndEntityProfile("Soft tokens cannot have a hardware token issuer.");
      }
      // If Hard token type check if hardware token issuer is among available hardware token issuers.
      if(tokentype > SecConst.TOKEN_SOFT && getUse(AVAILTOKENISSUER, 0) ){ // Hardware token.
        String[] availablehardtokenissuers;
        try{
          availablehardtokenissuers = getValue(AVAILTOKENISSUER, 0).split(SPLITCHAR);
        }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
        }
        if(availablehardtokenissuers == null)
            throw new UserDoesntFullfillEndEntityProfile("Error available hard token issuers is null.");
        found=false;
        for(int i=0; i < availablehardtokenissuers.length;i++){
            if( Integer.parseInt(availablehardtokenissuers[i]) == hardwaretokenissuerid)
                found=true;
        }
        
        if(!found)
            throw new UserDoesntFullfillEndEntityProfile("Couldn't find hard token issuers among available hard token issuers.");
      }
      
     // Check if ca id is among available ca ids.
      String[] availablecaids;
      try{
        availablecaids = getValue(AVAILCAS,0).split(SPLITCHAR);
      }catch(Exception e){
          throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablecaids == null)
          throw new UserDoesntFullfillEndEntityProfile("Error End Entity Profiles Available CAs is null.");
      found=false;
      for(int i=0; i < availablecaids.length;i++){
          int tmp = Integer.parseInt(availablecaids[i]);
          if( tmp == caid || tmp == SecConst.ALLCAS)
              found=true;
      }
      
      if(!found)
          throw new UserDoesntFullfillEndEntityProfile("Couldn't find CA among End Entity Profiles Available CAs.");      
    }
    
    public void doesPasswordFulfillEndEntityProfile(String password, boolean clearpwd)
      throws UserDoesntFullfillEndEntityProfile{
    	
		boolean fullfillsprofile = true;
		if(useAutoGeneratedPasswd()){
		  if(password !=null)
			throw new UserDoesntFullfillEndEntityProfile("Autogenerated password must have password==null");
		}else{           		            
		 if(!isModifyable(EndEntityProfile.PASSWORD,0)){
		   if(!password.equals(getValue(EndEntityProfile.PASSWORD,0)))		   
			 fullfillsprofile=false;
		 } 
		 else
		   if(isRequired(EndEntityProfile.PASSWORD,0)){
			 if((!clearpwd && password == null) || (password != null && password.trim().equals("")))			
			   fullfillsprofile=false;
		   }
		}
           
		 if(clearpwd && isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) && getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.FALSE)){		 	
			 fullfillsprofile=false;
		 }
		 
		 if(!fullfillsprofile)
		   throw new UserDoesntFullfillEndEntityProfile("Password doesn't fullfill profile.");
    }

    public Object clone() throws CloneNotSupportedException {
      EndEntityProfile clone = new EndEntityProfile();
      HashMap clonedata = (HashMap) clone.saveData();

      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key,data.get(key));
      }

      clone.loadData(clonedata);
      return clone;
    }

    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade() {
        log.debug(">upgrade");
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            log.info("upgrading entityprofile with version "+getVersion());
            // New version of the class, upgrade
            if(getVersion() < 1){
                ArrayList numberarray = (ArrayList)   data.get(NUMBERARRAY);
                while(numberarray.size() < 37){
                   numberarray.add(new Integer(0));
                }
                data.put(NUMBERARRAY,numberarray);
              }
            if(getVersion() < 2){
                ArrayList numberarray = (ArrayList)   data.get(NUMBERARRAY);
                while(numberarray.size() < 39){
                   numberarray.add(new Integer(0));
                }
                data.put(NUMBERARRAY,numberarray);
                
                addField(AVAILCAS);
                addField(DEFAULTCA);
                setRequired(AVAILCAS,0,true);
                setRequired(DEFAULTCA,0,true);
            }
            if(getVersion() < 3){
                setNotificationSubject("");
                setNotificationSender("");
                setNotificationMessage("");
            }
            
            if(getVersion() < 4){
                ArrayList numberoffields = (ArrayList)   data.get(NUMBERARRAY);                
                for(int i =numberoffields.size(); i < dataConstants.size(); i++){
                  numberoffields.add(new Integer(0));
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
                  numberoffields.add(new Integer(0));
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
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.debug("<upgrade");
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
     * Used for both email and upn fields
     * 
     */
    private void checkIfDomainFullfillProfile(String field, int number, String nameAndDomain, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!nameAndDomain.trim().equals("") && nameAndDomain.indexOf('@') == -1)
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". There must have '@' in the field.");
    	
    	String domain = nameAndDomain.substring(nameAndDomain.indexOf('@') + 1);    	    	
    	
        if(!getUse(field,number) && !nameAndDomain.trim().equals(""))
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
      
        if(!isModifyable(field,number) && !nameAndDomain.equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(domain.equals(values[i].trim()))
              exists = true;
          }
          if(!exists)
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
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
    	    	
    	if(!country.trim().equals("") && country.trim().length() != 2)
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be of length two.");
    	
        if(!getUse(field,number) && !country.trim().equals(""))
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
      
        if(!isModifyable(field,number) && !country.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(country.equals(values[i].trim()))
              exists = true;
          }
          if(!exists)
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
        }
    }
    
    /**
     * Used to check if it is an M or an F
     * 
     */
    private void checkIfGenderFullfillProfile(String field, int number, String gender, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!gender.trim().equals("") && !(gender.equalsIgnoreCase("m") || gender.equalsIgnoreCase("f")))
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be M or F.");
    	
        if(!getUse(field,number) && !gender.trim().equals(""))
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
      
        if(!isModifyable(field,number) && !gender.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(gender.equals(values[i].trim()))
              exists = true;
          }
          if(!exists)
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
        }
    }

    /**
     * Used for date strings, should be YYYYMMDD
     * 
     */
    private void checkIfDateFullfillProfile(String field, int number, String date, String text) throws UserDoesntFullfillEndEntityProfile {
    	    	
    	if(!date.trim().equals("") && date.trim().length() != 8)
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be of length eight.");
    	if(!date.trim().equals("") && !StringUtils.isNumeric(date.trim()))
    		throw new UserDoesntFullfillEndEntityProfile("Invalid " + text + ". Must be only numbers.");
    	
        if(!getUse(field,number) && !date.trim().equals(""))
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
      
        if(!isModifyable(field,number) && !date.trim().equals("")){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(date.equals(values[i].trim()))
              exists = true;
          }
          if(!exists)
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
        }
    }
    
    private void checkIfDataFullfillProfile(String field, int number, String data, String text, String email) throws UserDoesntFullfillEndEntityProfile {

    	if(data == null && !field.equals(EMAIL))
    		throw new UserDoesntFullfillEndEntityProfile("Field " +  text + " cannot be null.");

    	if(data !=null)
    		if(!getUse(field,number) && !data.trim().equals(""))
    			throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");

    	if(field.equals(DnComponents.DNEMAIL) || field.equals(DnComponents.RFC822NAME)){
    		if(isRequired(field,number)){
    			if(!data.trim().equals(email.trim()))
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
    				if(data.equals(values[i].trim()))
    					exists = true;
    			}
    			if(!exists)
    				throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
    		}
    	}
    }

    private void checkIfAllRequiredFieldsExists(DNFieldExtractor subjectdnfields, DNFieldExtractor subjectaltnames, DNFieldExtractor subjectdirattrs, String username, String email)  throws UserDoesntFullfillEndEntityProfile{
        int size;

        // Check if Username exists.
        if(isRequired(USERNAME,0)){
          if(username == null || username.trim().equals(""))
            throw new UserDoesntFullfillEndEntityProfile("Username cannot be empty or null.");
        }

        // Check if required Email fields exists.
        if(isRequired(EMAIL,0)){
          if(email == null || email.trim().equals(""))
            throw new UserDoesntFullfillEndEntityProfile("Email address cannot be empty or null.");
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
               if(isRequired(dnfields[i],j))
                 if(subjectdnfields.getField(dnFieldExtractorIds[i].intValue(),j).trim().equals(""))
                  throw new UserDoesntFullfillEndEntityProfile("Subject DN field '" + dnfields[i] + "' must exist.");
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
        		size = getNumberOfField(altnamefields[i]);
        		for(int j = 0; j < size; j++){
        			if(isRequired(altnamefields[i],j))
        				if(subjectaltnames.getField(altNameFieldExtractorIds[i].intValue(),j).trim().equals(""))
        					throw new UserDoesntFullfillEndEntityProfile("Subject Alterntive Name field '" + altnamefields[i] + "' must exist.");
        		}
        	}
        }

        // Check if all required subject directory attribute fields exists.
        String[] dirattrfields = getSubjectDirAttrProfileFields();
        Integer[] dirAttrFieldExtractorIds = (Integer[])DnComponents.getDirAttrDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dirattrfields.length; i++){        	
        	size = getNumberOfField(dirattrfields[i]);
        	for(int j = 0; j < size; j++){
        		if(isRequired(dirattrfields[i],j))
        			if(subjectdirattrs.getField(dirAttrFieldExtractorIds[i].intValue(),j).trim().equals(""))
        				throw new UserDoesntFullfillEndEntityProfile("Subject Directory Attribute field '" + dirattrfields[i] + "' must exist.");
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
            if(getNumberOfField(dnfields[i]) < subjectdnfields.getNumberOfFields(dnFieldExtractorIds[i].intValue()))
              throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + dnfields[i] + " fields in Subject DN.");
        }

         // Check number of subject alternate name fields.
        String[] altnamefields = getSubjectAltnameProfileFields();
        Integer[] altNameFieldExtractorIds = (Integer[])DnComponents.getAltNameDnIds().toArray(new Integer[0]);
        for(int i = 0; i < altnamefields.length; i++){
          if(getNumberOfField(altnamefields[i]) < subjectaltnames.getNumberOfFields(altNameFieldExtractorIds[i].intValue()))
           throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + altnamefields[i] + " fields in Subject Alternative Name.");
        }

        // Check number of subject directory attribute fields.
        String[] dirattrfields = getSubjectDirAttrProfileFields();
        Integer[] dirAttrFieldExtractorIds = (Integer[])DnComponents.getDirAttrDnIds().toArray(new Integer[0]);
        for(int i = 0; i < dirattrfields.length; i++){
          if(getNumberOfField(dirattrfields[i]) < subjectdirattrs.getNumberOfFields(dirAttrFieldExtractorIds[i].intValue()))
           throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + dirattrfields[i] + " fields in Subject Directory Attributes.");
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
      numberarray.set(parameter, new Integer(((Integer) numberarray.get(parameter)).intValue() + 1));
    }

    private void  decrementFieldnumber(int parameter){
      ArrayList numberarray = (ArrayList) data.get(NUMBERARRAY);
      numberarray.set(parameter, new Integer(((Integer) numberarray.get(parameter)).intValue() - 1));
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


    private static final String NUMBERARRAY               = "NUMBERARRAY";
    private static final String SUBJECTDNFIELDORDER       = "SUBJECTDNFIELDORDER";
    private static final String SUBJECTALTNAMEFIELDORDER  = "SUBJECTALTNAMEFIELDORDER";
    private static final String SUBJECTDIRATTRFIELDORDER  = "SUBJECTDIRATTRFIELDORDER";
    
    private static final String NOTIFICATIONSENDER     = "NOTIFICATIONSENDER";
    private static final String NOTIFICATIONSUBJECT    = "NOTIFICATIONSSUBJECT";
    private static final String NOTIFICATIONMESSAGE   = "NOTIFICATIONSMESSAGE";

    private static final String REUSECERTIFICATE = "REUSECERTIFICATE";
    private static final String REVERSEFFIELDCHECKS = "REVERSEFFIELDCHECKS"; 
    
    private static final String PRINTINGUSE            = "PRINTINGUSE";
    private static final String PRINTINGDEFAULT        = "PRINTINGDEFAULT";
    private static final String PRINTINGREQUIRED       = "PRINTINGREQUIRED";
    private static final String PRINTINGCOPIES         = "PRINTINGCOPIES";
    private static final String PRINTINGPRINTERNAME    = "PRINTINGPRINTERNAME";
    private static final String PRINTINGSVGFILENAME    = "PRINTINGSVGFILENAME";
    private static final String PRINTINGSVGDATA        = "PRINTINGSVGDATA";
    // Private fields.


}
