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
 
package se.anatom.ejbca.ra.raadmin;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.UpgradeableDataHashMap;
import se.anatom.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * The model representation of an end entity profile, used in in the ra module
 * of ejbca web interface.
 *
 * @author  Philip Vendil
 * @version $Id: EndEntityProfile.java,v 1.23 2004-05-22 16:02:51 anatom Exp $
 */
public class EndEntityProfile extends UpgradeableDataHashMap implements java.io.Serializable, Cloneable {

    private static Logger log = Logger.getLogger(EndEntityProfile.class);
    public static final float LATEST_VERSION = 3;

    // Public constants
    // Type of data constants.
    public static final int VALUE      = 0;
    public static final int USE        = 1;
    public static final int ISREQUIRED = 2;
    public static final int MODIFYABLE = 3;

    // Field constants.
    public static final int USERNAME           = 0;
    public static final int PASSWORD           = 1;
    public static final int CLEARTEXTPASSWORD  = 2;
    public static final int OLDDNE             = 3;
    public static final int UID                = 4;
    public static final int COMMONNAME         = 5;
    public static final int SN                 = 6;
    public static final int GIVENNAME          = 7;
    public static final int INITIALS           = 8;
    public static final int SURNAME            = 9;
    public static final int TITLE              = 10;
    public static final int ORGANIZATIONUNIT   = 11;
    public static final int ORGANIZATION       = 12;
    public static final int LOCALE             = 13;
    public static final int STATE              = 14;
    public static final int DOMAINCOMPONENT    = 15;
    public static final int COUNTRY            = 16;
    public static final int RFC822NAME         = 17;
    public static final int DNSNAME            = 18;
    public static final int IPADDRESS          = 19;
    public static final int OTHERNAME          = 20;
    public static final int UNIFORMRESOURCEID  = 21;
    public static final int X400ADDRESS        = 22;
    public static final int DIRECTORYNAME      = 23;
    public static final int EDIPARTNAME        = 24;
    public static final int REGISTEREDID       = 25;
    public static final int EMAIL              = 26;
    public static final int ADMINISTRATOR      = 27;
    public static final int KEYRECOVERABLE     = 28;
    public static final int DEFAULTCERTPROFILE = 29;
    public static final int AVAILCERTPROFILES  = 30;
    public static final int DEFKEYSTORE        = 31;
    public static final int AVAILKEYSTORE      = 32;
    public static final int DEFAULTTOKENISSUER = 33;
    public static final int AVAILTOKENISSUER   = 34;
    public static final int SENDNOTIFICATION   = 35;
    public static final int UPN                = 36;
    public static final int DEFAULTCA          = 37;
    public static final int AVAILCAS           = 38;    
    
    
    public static final int NUMBEROFPARAMETERS = 39;

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
        ArrayList numberoffields = new ArrayList(NUMBEROFPARAMETERS);
        for(int i =0; i < NUMBEROFPARAMETERS; i++){
          numberoffields.add(new Integer(0));
        }
        data.put(NUMBERARRAY,numberoffields);
        data.put(SUBJECTDNFIELDORDER,new ArrayList());
        data.put(SUBJECTALTNAMEFIELDORDER,new ArrayList());

        for(int i=0; i < NUMBEROFPARAMETERS; i++){
          if(i != SENDNOTIFICATION &&
          	 i != OTHERNAME &&
			 i != X400ADDRESS &&
			 i != EDIPARTNAME &&
			 i != REGISTEREDID &&
			 i != DIRECTORYNAME ){	
             addField(i);
             setValue(i,0,"");
             setRequired(i,0,false);
             setUse(i,0,true);
             setModifyable(i,0,true);
          }  
        }

        setRequired(USERNAME,0,true);
        setRequired(PASSWORD,0,true);
        setRequired(COMMONNAME,0,true);
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
         ArrayList numberoffields = new ArrayList(NUMBEROFPARAMETERS);
         for(int i =0; i < NUMBEROFPARAMETERS; i++){
           numberoffields.add(new Integer(0));
         }

         data.put(NUMBERARRAY,numberoffields);
         data.put(SUBJECTDNFIELDORDER,new ArrayList());
         data.put(SUBJECTALTNAMEFIELDORDER,new ArrayList());

         addField(USERNAME);
         addField(PASSWORD);
         addField(COMMONNAME);
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
         setRequired(COMMONNAME,0,true);
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
      if(parameter >= OLDDNE && parameter <= COUNTRY){
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
        fieldorder.add(new Integer((NUMBERBOUNDRARY*parameter) + size));
        Collections.sort(fieldorder);
      }
      if((parameter >= RFC822NAME && parameter <= REGISTEREDID) || parameter == UPN){
        ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
        fieldorder.add(new Integer((NUMBERBOUNDRARY*parameter) + size));
      }
      incrementFieldnumber(parameter);
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

        // Remove from order list.
        if(parameter >= OLDDNE && parameter <= COUNTRY){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTDNFIELDORDER);
          int value = (NUMBERBOUNDRARY*parameter) + number;
          for(int i=0; i < fieldorder.size(); i++){
             if( value ==  ((Integer) fieldorder.get(i)).intValue()){
                fieldorder.remove(i);
                break;
             }
          }
        }

        if((parameter >= RFC822NAME && parameter <= REGISTEREDID) || parameter == UPN){
          ArrayList fieldorder = (ArrayList) data.get(SUBJECTALTNAMEFIELDORDER);
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
    public int getNumberOfField(int parameter){
      return ((Integer) ((ArrayList) data.get(NUMBERARRAY)).get(parameter)).intValue();
    }

    public void setValue(int parameter, int number, String value) {
       if(value !=null){
          value=value.trim();
          data.put(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), value);
       }else{
          data.put(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), "");
       }
    }

    public void setUse(int parameter, int number, boolean use){
          data.put(new Integer((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(use));
    }

    public void setRequired(int parameter, int number,  boolean isrequired) {
      data.put(new Integer((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(isrequired));
    }

    public void setModifyable(int parameter, int number, boolean changeable) {
       data.put(new Integer((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter), Boolean.valueOf(changeable));
    }

    public String getValue(int parameter, int number) {
      String returnval = (String) data.get(new Integer((VALUE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
      if(returnval != null)
        return returnval;
      else
        return "";
    }

    public boolean getUse(int parameter, int number){
      Boolean returnval = (Boolean) data.get(new Integer((USE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
      if(returnval != null)
        return returnval.booleanValue();
      else
        return false;
    }

    public boolean isRequired(int parameter, int number) {
      Boolean returnval = (Boolean) data.get(new Integer((ISREQUIRED*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
      if(returnval != null)
        return returnval.booleanValue();
      else
        return false;
    }

    public boolean isModifyable(int parameter, int number){
      Boolean returnval = (Boolean) data.get(new Integer((MODIFYABLE*FIELDBOUNDRARY) + (NUMBERBOUNDRARY*number) + parameter));
      if(returnval != null)
        return returnval.booleanValue();
      else
        return false;
    }

    public int getSubjectDNFieldOrderLength(){
      return ((ArrayList) data.get(SUBJECTDNFIELDORDER)).size();
    }
    public int getSubjectAltNameFieldOrderLength(){
      return ((ArrayList) data.get(SUBJECTALTNAMEFIELDORDER)).size();
    }

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

    public Collection getAvailableCAs(){
        ArrayList availablecaids = new ArrayList();
        availablecaids.addAll(Arrays.asList(getValue(AVAILCAS,0).split(SPLITCHAR)));
        return availablecaids;
    }
    
    public boolean useAutoGeneratedPasswd(){    	
    	return !this.getUse(EndEntityProfile.PASSWORD,0);
    }
    
    public String getAutoGeneratedPasswd(){
    	return PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(6,8);    	
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
    
    
    /** A function that takes an fieldid pointing to a coresponding id in UserView and DnFieldExctractor.
     *  For example : profileFieldIdToUserFieldIdMapper(EndEntityProfile.COMMONNAME) returns DnFieldExctractor.COMMONNAME.
     *
     *  Should only be used with subjectDN and Subject Alternative Names fields.
     */
    public static int profileFieldIdToUserFieldIdMapper(int parameter){
      return  PROFILEIDTOUSERIDMAPPER[parameter];
    }


    public void doesUserFullfillEndEntityProfile(String username, String password, String dn, String subjectaltname, String email,  int certificateprofileid,
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

      doesUserFullfillEndEntityProfileWithoutPassword(username, dn, subjectaltname, email,  certificateprofileid, administrator, keyrecoverable, sendnotification, tokentype, hardwaretokenissuerid, caid);

    }

    public void doesUserFullfillEndEntityProfileWithoutPassword(String username,  String dn, String subjectaltname, String email,  int certificateprofileid,
                                                                boolean administrator, boolean keyrecoverable, boolean sendnotification,
                                                                int tokentype, int hardwaretokenissuerid, int caid) throws UserDoesntFullfillEndEntityProfile{
      DNFieldExtractor subjectdnfields = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
      if (subjectdnfields.isIllegal()) {
          throw new UserDoesntFullfillEndEntityProfile("Subject IS is illegal.");
      }
      DNFieldExtractor subjectaltnames   = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
      if (subjectaltnames.isIllegal()) {
          throw new UserDoesntFullfillEndEntityProfile("Subject alt names are illegal.");
      }
      String dnfield;
      String[] values;

      // Check that no other than supported dn fields exists in the subject dn.
      if(subjectdnfields.existsOther())
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject DN Field found.");

      if(subjectaltnames.existsOther())
        throw new UserDoesntFullfillEndEntityProfile("Unsupported Subject Alternate Name Field found.");

      checkIfAllRequiredFieldsExists(subjectdnfields, subjectaltnames,  username, email);

      checkIfForIllegalNumberOfFields(subjectdnfields, subjectaltnames);

      // Check contents of username.
      checkIfDataFullfillProfile(USERNAME,0,username, "Username",null);

      //  Check Email address.
     if(email == null)
       email = "";
     checkIfEmailFullfillProfile(EMAIL,0,email,"Email");

      // Check contents of Subject DN fields.
      int[] subjectdnfieldnumbers = subjectdnfields.getNumberOfFields();
      for(int i = 0; i < DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY; i++){
        for(int j=0; j < subjectdnfieldnumbers[i]; j++){
          checkIfDataFullfillProfile(DNEXTRATORTOPROFILEMAPPER[i],j,subjectdnfields.getField(i,j), DNEXTRATORTOPROFILEMAPPERTEXTS[i], email);
        }
      }
       // Check contents of Subject Alternative Name fields.
      int[] subjectaltnamesnumbers = subjectaltnames.getNumberOfFields();
      for(int i = DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY; i < DNFieldExtractor.NUMBEROFFIELDS; i++){
        for(int j=0; j < subjectaltnamesnumbers[i-DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY]; j++){
          checkIfDataFullfillProfile(DNEXTRATORTOPROFILEMAPPER[i],j,subjectaltnames.getField(i,j), DNEXTRATORTOPROFILEMAPPERTEXTS[i], email);
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
      else{
        boolean found=false;
        for(int i=0; i < availablecertprofiles.length;i++){
          if( Integer.parseInt(availablecertprofiles[i]) == certificateprofileid)
            found=true;
        }

        if(!found)
           throw new UserDoesntFullfillEndEntityProfile("Couldn't find certificate profile among available certificate profiles.");
      }

      // Check if tokentype is among available  token types.
      String[] availablesofttokentypes;
      try{
        availablesofttokentypes = getValue(AVAILKEYSTORE,0).split(SPLITCHAR);
      }catch(Exception e){
        throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
      }
      if(availablesofttokentypes == null)
         throw new UserDoesntFullfillEndEntityProfile("Error available  token types is null.");
      else{
        boolean found=false;
        for(int i=0; i < availablesofttokentypes.length;i++){
          if( Integer.parseInt(availablesofttokentypes[i]) == tokentype)
            found=true;
        }
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
        else{
          boolean found=false;
          for(int i=0; i < availablehardtokenissuers.length;i++){
            if( Integer.parseInt(availablehardtokenissuers[i]) == hardwaretokenissuerid)
              found=true;
          }

          if(!found)
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
      if(availablecaids == null)
           throw new UserDoesntFullfillEndEntityProfile("Error End Entity Profiles Available CAs is null.");
      else{
        boolean found=false;
        for(int i=0; i < availablecaids.length;i++){
          int tmp = Integer.parseInt(availablecaids[i]);
          if( tmp == caid || tmp == SecConst.ALLCAS)
            found=true;
        }

        if(!found)
           throw new UserDoesntFullfillEndEntityProfile("Couldn't find CA among End Entity Profiles Available CAs.");
      }      
    }
    
    public void doesPasswordFulfillEndEntityProfile(String password, boolean clearpwd)
      throws UserDoesntFullfillEndEntityProfile{
    	
		boolean fullfillsprofile = true;
		if(useAutoGeneratedPasswd()){
		  if(password !=null)
			throw new UserDoesntFullfillEndEntityProfile("Autogenerated password must have password==null");
		}else{           		            
		 if(!isModifyable(EndEntityProfile.PASSWORD,0)){
		   if(!password.equals(getValue(EndEntityProfile.PASSWORD,0)));		   
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
        if(LATEST_VERSION != getVersion()){
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
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.debug("<upgrade");
    }

    // Private Methods

    private void checkIfEmailFullfillProfile(int field, int number, String email, String text) throws UserDoesntFullfillEndEntityProfile {
    	if(!email.trim().equals("") && email.indexOf('@') == -1)
    		throw new UserDoesntFullfillEndEntityProfile("Invalid email address. There must have '@' in address.");
    	
    	String emaildomain = email.substring(email.indexOf('@') + 1);    	    	
    	
        if(!getUse(field,number) && !email.trim().equals(""))
          throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");
      
        if(!isModifyable(field,number)){
          String[] values;
          try{
            values = getValue(field, number).split(SPLITCHAR);
          }catch(Exception e){
            throw new UserDoesntFullfillEndEntityProfile("Error parsing end entity profile.");
          }
          boolean exists = false;
          for(int i = 0; i < values.length ; i++){
            if(emaildomain.equals(values[i].trim()))
              exists = true;
          }
          if(!exists)
            throw new UserDoesntFullfillEndEntityProfile("Field " + text + " data didn't match requirement of end entity profile.");
        }
    }
    
    
    private void checkIfDataFullfillProfile(int field, int number, String data, String text, String email) throws UserDoesntFullfillEndEntityProfile {

    	if(data == null && field != EMAIL)
    		throw new UserDoesntFullfillEndEntityProfile("Field " +  text + " cannot be null.");

    	if(data !=null)
    		if(!getUse(field,number) && !data.trim().equals(""))
    			throw new UserDoesntFullfillEndEntityProfile(text + " cannot be used in end entity profile.");

    	if(field == OLDDNE || field == RFC822NAME){
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

    private void checkIfAllRequiredFieldsExists(DNFieldExtractor subjectdnfields, DNFieldExtractor subjectaltnames, String username, String email)  throws UserDoesntFullfillEndEntityProfile{
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
        for(int i = 0; i < SUBJECTDNFIELDS.length; i++){
          size = getNumberOfField(SUBJECTDNFIELDS[i]);
          for(int j = 0; j < size; j++){
            if(isRequired(SUBJECTDNFIELDS[i],j))
              if(subjectdnfields.getField(SUBJECTDNFIELDEXTRACTORNAMES[i],j).trim().equals(""))
                throw new UserDoesntFullfillEndEntityProfile("Subject DN field '" + SUBJECTDNFIELDNAMES[i] + "' must exist.");
          }
        }

         // Check if all required subject alternate name fields exists.
        for(int i = 0; i < SUBJECTALTNAMEFIELDS.length; i++){
          size = getNumberOfField(SUBJECTALTNAMEFIELDS[i]);
          for(int j = 0; j < size; j++){
            if(isRequired(SUBJECTALTNAMEFIELDS[i],j))
              if(subjectaltnames.getField(SUBJECTALTNAMEFIELDEXTRACTORNAMES[i],j).trim().equals(""))
                throw new UserDoesntFullfillEndEntityProfile("Subject DN field '" + SUBJECTALTNAMEFIELDNAMES[i] + "' must exist.");
          }
        }
    }


    private void  checkIfForIllegalNumberOfFields(DNFieldExtractor subjectdnfields, DNFieldExtractor subjectaltnames) throws UserDoesntFullfillEndEntityProfile{

        // Check number of subjectdn fields.
        for(int i = 0; i < SUBJECTDNFIELDS.length; i++){
            if(getNumberOfField(SUBJECTDNFIELDS[i]) < subjectdnfields.getNumberOfFields(SUBJECTDNFIELDEXTRACTORNAMES[i]))
              throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + SUBJECTDNFIELDNAMES[i] + " fields in Subject DN.");
        }

         // Check number of subject alternate name fields.
        for(int i = 0; i < SUBJECTALTNAMEFIELDS.length; i++){
          if(getNumberOfField(SUBJECTALTNAMEFIELDS[i]) < subjectaltnames.getNumberOfFields(SUBJECTALTNAMEFIELDEXTRACTORNAMES[i]))
           throw new UserDoesntFullfillEndEntityProfile("Wrong number of " + SUBJECTALTNAMEFIELDNAMES[i] + " fields in Subject Alternative Name.");
        }

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

    private static final int[] SUBJECTDNFIELDS              = {OLDDNE, UID, COMMONNAME, SN, GIVENNAME, INITIALS, SURNAME, TITLE, ORGANIZATIONUNIT, ORGANIZATION, LOCALE, STATE, DOMAINCOMPONENT, COUNTRY};
    private static final int[] SUBJECTDNFIELDEXTRACTORNAMES = { DNFieldExtractor.E,DNFieldExtractor.UID, DNFieldExtractor.CN, DNFieldExtractor.SN,
                                                               DNFieldExtractor.GIVENNAME,DNFieldExtractor.INITIALS,DNFieldExtractor.SURNAME, DNFieldExtractor.T,
                                                               DNFieldExtractor.OU, DNFieldExtractor.O, DNFieldExtractor.L,
                                                               DNFieldExtractor.ST, DNFieldExtractor.DC, DNFieldExtractor.C};
    private static final String[] SUBJECTDNFIELDNAMES       = {"Email Address (E)", "UID","CommonName (CN)", "SerialNumber (SN)", "GivenName (GivenName)",
                                                               "Initials (Initials)", "SurName (SurName)", "Title (T)", "OrganizationUnit (OU)", "Organization (O)",
                                                               "Location (L)", "State (ST)", "DomainComponent (DC)", "Country (C)"};


    private static final int[] SUBJECTALTNAMEFIELDS              = {DNSNAME,IPADDRESS, OTHERNAME, UNIFORMRESOURCEID, X400ADDRESS, DIRECTORYNAME, EDIPARTNAME, REGISTEREDID, RFC822NAME, UPN};
    private static final int[] SUBJECTALTNAMEFIELDEXTRACTORNAMES = {DNFieldExtractor.DNSNAME,DNFieldExtractor.IPADDRESS, DNFieldExtractor.OTHERNAME,
                                                                    DNFieldExtractor.URI, DNFieldExtractor.X400ADDRESS, DNFieldExtractor.DIRECTORYNAME,
                                                                    DNFieldExtractor.EDIPARTNAME, DNFieldExtractor.REGISTEREDID, DNFieldExtractor.RFC822NAME, DNFieldExtractor.UPN};
    private static final String[] SUBJECTALTNAMEFIELDNAMES       = {"DNSName", "IPAddress", "OtherName", "UniformResourceId (uri)", "X400Address", "DirectoryName",
                                                                    "EDIPartName","RegisteredId","RFC822Name", "UPN"};

    // Used to map constants of DNFieldExtractor to end entity profile constants.
    private static final int[] DNEXTRATORTOPROFILEMAPPER      = {OLDDNE, UID, COMMONNAME, SN, GIVENNAME, INITIALS, SURNAME,
                                                                 TITLE, ORGANIZATIONUNIT, ORGANIZATION, LOCALE,
                                                                 STATE, DOMAINCOMPONENT, COUNTRY, OTHERNAME, RFC822NAME, DNSNAME,
                                                                 IPADDRESS, X400ADDRESS, DIRECTORYNAME, EDIPARTNAME, UNIFORMRESOURCEID, REGISTEREDID, UPN};
    private static final String[] DNEXTRATORTOPROFILEMAPPERTEXTS = {"Email Address (E)", "UID", "CommonName (CN)", "SerialNumber (SN)",
                                                                    "GivenName (GivenName)", "Initials (Initials)", "SurName (SurName)",
                                                                    "Title (T)", "OrganizationUnit (OU)", "Organization (O)", "Location (L)",
                                                                    "State (ST)", "DomainComponent (DC)", "Country (C)", "OtherName", "RFC822Name", "DNSName",
                                                                    "IPAddress", "X400Address", "DirectoryName", "EDIPartName", "UniformResourceId (uri)", "RegisteredId", "UPN"};

    private static final int[] PROFILEIDTOUSERIDMAPPER        = {0,0,0, DNFieldExtractor.E, DNFieldExtractor.UID, DNFieldExtractor.CN, DNFieldExtractor.SN,
                                                                        DNFieldExtractor.GIVENNAME,DNFieldExtractor.INITIALS, DNFieldExtractor.SURNAME,
                                                                        DNFieldExtractor.T, DNFieldExtractor.OU, DNFieldExtractor.O,
                                                                        DNFieldExtractor.L ,DNFieldExtractor.ST,DNFieldExtractor.DC,
                                                                        DNFieldExtractor.C ,DNFieldExtractor.RFC822NAME ,DNFieldExtractor.DNSNAME,
                                                                        DNFieldExtractor.IPADDRESS ,DNFieldExtractor.OTHERNAME ,DNFieldExtractor.URI, DNFieldExtractor.X400ADDRESS,
                                                                        DNFieldExtractor.DIRECTORYNAME ,DNFieldExtractor.EDIPARTNAME ,DNFieldExtractor.REGISTEREDID,0,0,0,0,0,0,0,0,0,0,DNFieldExtractor.UPN};


    private static final String NUMBERARRAY               = "NUMBERARRAY";
    private static final String SUBJECTDNFIELDORDER       = "SUBJECTDNFIELDORDER";
    private static final String SUBJECTALTNAMEFIELDORDER  = "SUBJECTALTNAMEFIELDORDER";
    
    private static final String NOTIFICATIONSENDER     = "NOTIFICATIONSENDER";
    private static final String NOTIFICATIONSUBJECT    = "NOTIFICATIONSSUBJECT";
    private static final String NOTIFICATIONMESSAGE   = "NOTIFICATIONSMESSAGE";
    // Private fields.


}
