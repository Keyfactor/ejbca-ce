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
 
package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.fileupload.DiskFileUpload;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.EnhancedEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfileWithAdressLabel;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfileWithPINEnvelope;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfileWithReceipt;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfileWithVisualLayout;
import org.ejbca.core.model.hardtoken.profiles.IAdressLabelSettings;
import org.ejbca.core.model.hardtoken.profiles.IPINEnvelopeSettings;
import org.ejbca.core.model.hardtoken.profiles.IReceiptSettings;
import org.ejbca.core.model.hardtoken.profiles.IVisualLayoutSettings;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.TurkishEIDProfile;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;


/**
 * Contains help methods used to parse a hard token profile jsp page requests.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class EditHardTokenProfileJSPHelper implements java.io.Serializable {
	
    private static final long serialVersionUID = -310960445499242212L;
  
    public static final String ACTION                              = "action";
	public static final String ACTION_EDIT_HARDTOKENPROFILES       = "edithardtokenprofiles";
	public static final String ACTION_EDIT_HARDTOKENPROFILE        = "edithardtokenprofile";
    public static final String ACTION_UPLOADENVELOPETEMP           = "uploadenvelopetemp";
	public static final String ACTION_UPLOADVISUALTEMP             = "uploadvisualtemp";
	public static final String ACTION_UPLOADRECEIPTTEMP            = "uploadreceipttemp";
	public static final String ACTION_UPLOADADRESSLABELTEMP        = "uploadadresstemp";

	public static final String ACTION_CHANGE_PROFILETYPE           = "changeprofiletype";


	public static final String CHECKBOX_VALUE           = HardTokenProfile.TRUE;

//	  Used in profiles.jsp
	public static final String BUTTON_EDIT_HARDTOKENPROFILES      = "buttonedithardtokenprofile"; 
	public static final String BUTTON_DELETE_HARDTOKENPROFILES    = "buttondeletehardtokenprofile";
	public static final String BUTTON_ADD_HARDTOKENPROFILES       = "buttonaddhardtokenprofile"; 
	public static final String BUTTON_RENAME_HARDTOKENPROFILES    = "buttonrenamehardtokenprofile";
	public static final String BUTTON_CLONE_HARDTOKENPROFILES     = "buttonclonehardtokenprofile";

	public static final String SELECT_HARDTOKENPROFILES           = "selecthardtokenprofile";
	public static final String TEXTFIELD_HARDTOKENPROFILESNAME    = "textfieldhardtokenprofilename";
	public static final String HIDDEN_HARDTOKENPROFILENAME        = "hiddenhardtokenprofilename";
 
//	 Buttons used in profile.jsp
	public static final String BUTTON_SAVE              = "buttonsave";
	public static final String BUTTON_CANCEL            = "buttoncancel";
	public static final String BUTTON_UPLOADENVELOPETEMP= "buttonuploadenvelopetemplate"; 
	public static final String BUTTON_UPLOADVISUALTEMP  = "buttonuploadvisualtemplate";
	public static final String BUTTON_UPLOADRECEIPTTEMP = "buttonuploadreceipttemplate";
	public static final String BUTTON_UPLOADADRESSLABELTEMP  = "buttonuploadadresslabeltemplate";
	public static final String BUTTON_UPLOADFILE        = "buttonuploadfile";
 
	public static final String TYPE_SWEDISHEID          = "typeswedisheid";
	public static final String TYPE_ENCHANCEDEID        = "typeenchancedeid";
	public static final String TYPE_TURKISHEID          = "typeturkisheid";

	public static final String TEXTFIELD_VISUALVALIDITY = "textfieldvisualvalidity";
	public static final String TEXTFIELD_SNPREFIX       = "textfieldsnprefix";

	public static final String CHECKBOX_EREASBLE        = "checkboxereasable";
	public static final String CHECKBOX_CERTWRITABLE    = "checkboxcertwritable";
	public static final String CHECKBOX_KEYRECOVERABLE  = "checkboxkeyrecoverable";
	public static final String CHECKBOX_REUSEOLDCERT    = "checkboxreuseoldcert";
	public static final String CHECKBOX_USEIDENTICALPINS= "useidenticalpins";

	public static final String HIDDEN_HARDTOKENTYPE     = "hiddenhardtokentype";

	public static final String SELECT_HARDTOKENTYPE      = "selecthardtokentype";
	public static final String SELECT_CERTIFICATEPROFILE = "selectcertificateprofile";
	public static final String SELECT_CA                 = "selectca";
	public static final String SELECT_PINTYPE            = "selectpintype";
	public static final String SELECT_MINKEYLENGTH       = "selectminkeylength";
	public static final String SELECT_ENVELOPETYPE       = "selectenvelopetype";
	public static final String SELECT_NUMOFENVELOPECOPIES= "selectenvelopecopies";
	public static final String SELECT_RECEIPTTYPE        = "selectreceipttype";
	public static final String SELECT_NUMOFRECEIPTCOPIES = "selectreceiptcopies";
	public static final String SELECT_ADRESSLABELTYPE    = "selectadresslabeltype";
	public static final String SELECT_NUMOFADRESSLABELCOPIES = "selectadresslabelcopies";
	public static final String SELECT_VISUALLAYOUTTYPE   = "selectvisuallayouttype";
	public static final String SELECT_NUMOFTOKENCOPIES   = "selectnumoftokencopies";
	public static final String SELECT_MINPINLENGTH       = "selectminpinlength";
	
	public static final String FILE_TEMPLATE             = "filetemplate";
	
	public static final int UPLOADMODE_ENVELOPE     = 0; 
	public static final int UPLOADMODE_VISUAL       = 1;
	public static final int UPLOADMODE_RECEIPT      = 2;
	public static final int UPLOADMODE_ADRESSLABEL  = 3;
    
    public static final String PAGE_HARDTOKENPROFILE = "hardtokenprofilepage.jspf";
    public static final String PAGE_HARDTOKENPROFILES = "hardtokenprofilespage.jspf";
    public static final String PAGE_UPLOADTEMPLATE = "uploadtemplate.jspf";

    /** Creates new LogInterfaceBean */
    public EditHardTokenProfileJSPHelper(){     	    	
    }
    // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(EjbcaWebBean ejbcawebbean, HardTokenInterfaceBean hardtokenbean) throws  Exception{

      if(!initialized){
        this.hardtokenbean = hardtokenbean;
        initialized = true;
		issuperadministrator = false;
		try{
		  issuperadministrator = ejbcawebbean.isAuthorizedNoLog(StandardRules.ROLE_ROOT.resource());
		}catch(AuthorizationDeniedException ade){}
      }
    }
    
    public String parseRequest(HttpServletRequest request) throws AuthorizationDeniedException{
      String includefile = PAGE_HARDTOKENPROFILES; 
	  String profile = null;
	  HardTokenProfileDataHandler handler  = hardtokenbean.getHardTokenProfileDataHandler();	
      String action = null;

	  InputStream file = null;
	  
      boolean buttonupload = false;
      String filename = null;

      try {
        RequestHelper.setDefaultCharacterEncoding(request);
    } catch (UnsupportedEncodingException e1) {
        // ignore
    }

	  if(FileUploadBase.isMultipartContent(request)){
	  	try{     	  	
		  DiskFileUpload upload = new DiskFileUpload();
		  upload.setSizeMax(2000000);                   
		  upload.setSizeThreshold(1999999);
		  @SuppressWarnings("unchecked")
        List<FileItem> items = upload.parseRequest(request);     

		  Iterator<FileItem> iter = items.iterator();
		  while (iter.hasNext()) {     
		  FileItem item = iter.next();

		    if (item.isFormField()) {         
			  if(item.getFieldName().equals(ACTION)) {
			    action = item.getString(); 
			  }
			  if(item.getFieldName().equals(HIDDEN_HARDTOKENPROFILENAME)) {
			    profilename = item.getString();
			  }
			  if(item.getFieldName().equals(BUTTON_CANCEL)) {
			      // do nothing
              }
			  if(item.getFieldName().equals(BUTTON_UPLOADFILE)) {
			    buttonupload = true;
			  }
		    }else{         
			  file = item.getInputStream();
			  filename = item.getName(); 
		    }
		  }
	  	}catch(IOException e){
	  	  fileuploadfailed = true;
		  includefile=PAGE_HARDTOKENPROFILE;	  
	  	}catch(FileUploadException e){
		  fileuploadfailed = true;	  
		  includefile=PAGE_HARDTOKENPROFILE;
	    }
	  }else{
		action = request.getParameter(ACTION);
	  }



	  if( action != null){
		if( action.equals(ACTION_EDIT_HARDTOKENPROFILES)){						
		  if( request.getParameter(BUTTON_EDIT_HARDTOKENPROFILES) != null){
			  // Display  profilepage.jsp
			 profile = request.getParameter(SELECT_HARDTOKENPROFILES);
			 if(profile != null){
			   if(!profile.trim().equals("")){
				   includefile=PAGE_HARDTOKENPROFILE;
				   this.profilename = profile;
				   this.profiledata = handler.getHardTokenProfile(profilename);  
			   } else { 
				profile= null;
			  } 
			}
			if(profile == null){   
			  includefile=PAGE_HARDTOKENPROFILES;     
			}
		  }
		  if( request.getParameter(BUTTON_DELETE_HARDTOKENPROFILES) != null) {
			  // Delete profile and display profilespage. 
			  profile = request.getParameter(SELECT_HARDTOKENPROFILES);
			  if(profile != null){
				if(!profile.trim().equals("")){      					        
					hardtokenprofiledeletefailed = handler.removeHardTokenProfile(profile);          
				}
			  }
			  includefile=PAGE_HARDTOKENPROFILES;             
		  }
		  if( request.getParameter(BUTTON_RENAME_HARDTOKENPROFILES) != null){ 
			 // Rename selected profile and display profilespage.
		   String newhardtokenprofilename = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
		   String oldhardtokenprofilename = request.getParameter(SELECT_HARDTOKENPROFILES);
		   if(oldhardtokenprofilename != null && newhardtokenprofilename != null){
			 if(!newhardtokenprofilename.trim().equals("") && !oldhardtokenprofilename.trim().equals("")){
			   try{
				 handler.renameHardTokenProfile(oldhardtokenprofilename.trim(),newhardtokenprofilename.trim());
			   }catch( HardTokenProfileExistsException e){
				  hardtokenprofileexists=true;
			   }
			 }
		   }      
		   includefile=PAGE_HARDTOKENPROFILES; 
		  }
		  if( request.getParameter(BUTTON_ADD_HARDTOKENPROFILES) != null){
			 // Add profile and display profilespage.
			 profile = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
			 if(profile != null){
			   if(!profile.trim().equals("")){          
				 try{
				   if(!handler.addHardTokenProfile(profile.trim(), new SwedishEIDProfile())){
					  profilemalformed = true;  
				   }
				 }catch( HardTokenProfileExistsException e){
				   hardtokenprofileexists=true;
				 }             
			   }      
			 }
			 includefile=PAGE_HARDTOKENPROFILES; 
		  }
		  if( request.getParameter(BUTTON_CLONE_HARDTOKENPROFILES) != null){
			 // clone profile and display profilespage.
		   String newhardtokenprofilename = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
		   String oldhardtokenprofilename = request.getParameter(SELECT_HARDTOKENPROFILES);
		   if(oldhardtokenprofilename != null && newhardtokenprofilename != null){
			 if(!newhardtokenprofilename.trim().equals("") && !oldhardtokenprofilename.trim().equals("")){            
			   try{ 
				 handler.cloneHardTokenProfile(oldhardtokenprofilename.trim(),newhardtokenprofilename.trim());
			   }catch(HardTokenProfileExistsException e){
				   hardtokenprofileexists=true;
			   }
			 }
		   }      
			  includefile=PAGE_HARDTOKENPROFILES; 
		  }
		}
		
		if( action.equals(ACTION_EDIT_HARDTOKENPROFILE)){
			 // Display edit access rules page.
		   profile = request.getParameter(HIDDEN_HARDTOKENPROFILENAME);
		   if(profile != null){
			 if(!profile.trim().equals("")){
			   if(request.getParameter(BUTTON_SAVE) != null ||
			      request.getParameter(BUTTON_UPLOADENVELOPETEMP) != null ||
				  request.getParameter(BUTTON_UPLOADVISUALTEMP) != null ||
				  request.getParameter(BUTTON_UPLOADRECEIPTTEMP) != null ||
				  request.getParameter(BUTTON_UPLOADADRESSLABELTEMP) != null ){
		
             
				 if(profiledata == null){               
				   String tokentype = request.getParameter(HIDDEN_HARDTOKENTYPE);
				   if(tokentype.equals(TYPE_SWEDISHEID)) {
					 profiledata = new SwedishEIDProfile();
				   }
				   if(tokentype.equals(TYPE_ENCHANCEDEID)) {
					 profiledata = new EnhancedEIDProfile();
				   }
				   if(tokentype.equals(TYPE_TURKISHEID)) {
					 profiledata = new TurkishEIDProfile();
				   }
				 }
				 // Save changes.
                    
				 // General settings   
				 String value = request.getParameter(TEXTFIELD_SNPREFIX);
				 if(value != null){                              
				   value = value.trim();
				   profiledata.setHardTokenSNPrefix(value); 
				 }
				 value = request.getParameter(CHECKBOX_EREASBLE);
				 if(value != null){                              
				   profiledata.setEreasableToken(value.equals(CHECKBOX_VALUE));
				 }else {
				   profiledata.setEreasableToken(false);
				 }
				 value = request.getParameter(SELECT_NUMOFTOKENCOPIES);
				 if(value != null){                              				   
				   profiledata.setNumberOfCopies(Integer.parseInt(value)); 
				 }

				value = request.getParameter(CHECKBOX_USEIDENTICALPINS);
				if(value != null){                              
				  profiledata.setGenerateIdenticalPINForCopies(value.equals(CHECKBOX_VALUE));
				}else {
				  profiledata.setGenerateIdenticalPINForCopies(false);
				}
				if(profiledata instanceof HardTokenProfileWithPINEnvelope){
					value = request.getParameter(SELECT_ENVELOPETYPE);
					if(value != null) {                                               
						((HardTokenProfileWithPINEnvelope) profiledata).setPINEnvelopeType(Integer.parseInt(value));
					}
					value = request.getParameter(SELECT_NUMOFENVELOPECOPIES);
					if(value != null) {                                               
						((HardTokenProfileWithPINEnvelope) profiledata).setNumberOfPINEnvelopeCopies(Integer.parseInt(value));
					}
					value = request.getParameter(TEXTFIELD_VISUALVALIDITY);
					if(value != null) {                                        
						((HardTokenProfileWithPINEnvelope) profiledata).setVisualValidity(Integer.parseInt(value));       													
					}
				}
  
				 if(profiledata instanceof HardTokenProfileWithVisualLayout){
				   HardTokenProfileWithVisualLayout visprof = (HardTokenProfileWithVisualLayout) profiledata;
				   value = request.getParameter(SELECT_VISUALLAYOUTTYPE);
				   if(value != null) {                                        
				     visprof.setVisualLayoutType(Integer.parseInt(value));
				   }
				 }
				 
				 if(profiledata instanceof HardTokenProfileWithReceipt){
					   value = request.getParameter(SELECT_RECEIPTTYPE);
					   if(value != null) {                                               
						 ((HardTokenProfileWithReceipt) profiledata).setReceiptType(Integer.parseInt(value));
					   }
					   value = request.getParameter(SELECT_NUMOFRECEIPTCOPIES);
					   if(value != null) {                                               
						((HardTokenProfileWithReceipt) profiledata).setNumberOfReceiptCopies(Integer.parseInt(value));
					   }
				 }
				 if(profiledata instanceof HardTokenProfileWithAdressLabel){
					   value = request.getParameter(SELECT_ADRESSLABELTYPE);
					   if(value != null) {                                               
						 ((HardTokenProfileWithAdressLabel) profiledata).setAdressLabelType(Integer.parseInt(value));
					   }
					   value = request.getParameter(SELECT_NUMOFADRESSLABELCOPIES);
					   if(value != null) {                                               
						((HardTokenProfileWithAdressLabel) profiledata).setNumberOfAdressLabelCopies(Integer.parseInt(value));
					   }
				 }

				 if(profiledata instanceof SwedishEIDProfile){
                   SwedishEIDProfile sweprof = (SwedishEIDProfile) profiledata;
                   
				   value = request.getParameter(SELECT_MINKEYLENGTH);
				   if(value!= null){
					 int val = Integer.parseInt(value);				   
					 sweprof.setMinimumKeyLength(SwedishEIDProfile.CERTUSAGE_SIGN, val);
					 sweprof.setMinimumKeyLength(SwedishEIDProfile.CERTUSAGE_AUTHENC, val);
					 sweprof.setKeyType(SwedishEIDProfile.CERTUSAGE_SIGN, EIDProfile.KEYTYPE_RSA);
					 sweprof.setKeyType(SwedishEIDProfile.CERTUSAGE_AUTHENC, EIDProfile.KEYTYPE_RSA);
				   }
				   value = request.getParameter(CHECKBOX_CERTWRITABLE);
				   if(value != null){                              
					   sweprof.setCertWritable(SwedishEIDProfile.CERTUSAGE_SIGN, value.equals(CHECKBOX_VALUE));
					   sweprof.setCertWritable(SwedishEIDProfile.CERTUSAGE_AUTHENC, value.equals(CHECKBOX_VALUE));
				   }else{
					   sweprof.setCertWritable(SwedishEIDProfile.CERTUSAGE_SIGN, false);
					   sweprof.setCertWritable(SwedishEIDProfile.CERTUSAGE_AUTHENC, false);
				   }
				   	  
                   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "0");
                   if(value!= null) {
                     sweprof.setCertificateProfileId(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
                   }
				   value = request.getParameter(SELECT_CA + "0");
				   if(value!= null) {
					   sweprof.setCAId(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_PINTYPE + "0");
				   if(value!= null) {
					   sweprof.setPINType(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_MINPINLENGTH + "0");
				   if(value!= null) {
					   sweprof.setMinimumPINLength(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value)); 
				   }
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "1");
				   if(value!= null) {
					   sweprof.setCertificateProfileId(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_CA + "1");
				   if(value!= null) {
					   sweprof.setCAId(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_PINTYPE + "1");
				   if(value!= null) {
				     sweprof.setPINType(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_MINPINLENGTH + "1");
				   if(value!= null) {
					 sweprof.setMinimumPINLength(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));                  
				   }
				 }

				 if(profiledata instanceof TurkishEIDProfile){
					   TurkishEIDProfile turkprof = (TurkishEIDProfile) profiledata;
	                   
					   value = request.getParameter(SELECT_MINKEYLENGTH);
					   if(value!= null){
						 int val = Integer.parseInt(value);				   
						 turkprof.setMinimumKeyLength(TurkishEIDProfile.CERTUSAGE_SIGN, val);
						 turkprof.setMinimumKeyLength(TurkishEIDProfile.CERTUSAGE_AUTHENC, val);
						 turkprof.setKeyType(TurkishEIDProfile.CERTUSAGE_SIGN, EIDProfile.KEYTYPE_RSA);
						 turkprof.setKeyType(TurkishEIDProfile.CERTUSAGE_AUTHENC, EIDProfile.KEYTYPE_RSA);
					   }
					   value = request.getParameter(CHECKBOX_CERTWRITABLE);
					   if(value != null){                              
						   turkprof.setCertWritable(TurkishEIDProfile.CERTUSAGE_SIGN, value.equals(CHECKBOX_VALUE));
						   turkprof.setCertWritable(TurkishEIDProfile.CERTUSAGE_AUTHENC, value.equals(CHECKBOX_VALUE));
					   }else{
						   turkprof.setCertWritable(TurkishEIDProfile.CERTUSAGE_SIGN, false);
						   turkprof.setCertWritable(TurkishEIDProfile.CERTUSAGE_AUTHENC, false);
					   }
					   	  
	                   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "0");
	                   if(value!= null) {
	                	   turkprof.setCertificateProfileId(TurkishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
	                   }
					   value = request.getParameter(SELECT_CA + "0");
					   if(value!= null) {
						   turkprof.setCAId(TurkishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
					   }
					   value = request.getParameter(SELECT_PINTYPE + "0");
					   if(value!= null) {
						   turkprof.setPINType(TurkishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
					   }
					   value = request.getParameter(SELECT_MINPINLENGTH + "0");
					   if(value!= null) {
						   turkprof.setMinimumPINLength(TurkishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value)); 
					   }
					   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "1");
					   if(value!= null) {
						   turkprof.setCertificateProfileId(TurkishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
					   }
					   value = request.getParameter(SELECT_CA + "1");
					   if(value!= null) {
						   turkprof.setCAId(TurkishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
					   }
			     }				 
				 
				 if(profiledata instanceof EnhancedEIDProfile){
				   EnhancedEIDProfile enhprof = (EnhancedEIDProfile) profiledata;

				   value = request.getParameter(SELECT_MINKEYLENGTH);
				   if(value!= null){				   
				   	 int val = Integer.parseInt(value);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_SIGN, val);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_AUTH, val);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_ENC, val);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_SIGN, EIDProfile.KEYTYPE_RSA);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_ENC, EIDProfile.KEYTYPE_RSA);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_ENC, EIDProfile.KEYTYPE_RSA);
				   }	  
				   
				   value = request.getParameter(CHECKBOX_CERTWRITABLE);
				   if(value != null){                              
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_SIGN, value.equals(CHECKBOX_VALUE));
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_AUTH, value.equals(CHECKBOX_VALUE));
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_ENC, value.equals(CHECKBOX_VALUE));
				   }else{
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_SIGN, false);
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_AUTH, false);
					   enhprof.setCertWritable(EnhancedEIDProfile.CERTUSAGE_ENC, false);
				   }
				   
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "0");
				   if(value!= null) {
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_CA + "0");
				   if(value!= null) {
					 enhprof.setCAId(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_PINTYPE + "0");
				   if(value!= null) {
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_MINPINLENGTH + "0");
				   if(value!= null) {
				   	 enhprof.setMinimumPINLength(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   }
                   enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_SIGN, false); 
                    
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "1");
				   if(value!= null) {
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_CA + "1");
				   if(value!= null) {
					 enhprof.setCAId(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_PINTYPE + "1");
				   if(value!= null) {
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_MINPINLENGTH + "1");
				   if(value!= null) {
				   	 enhprof.setMinimumPINLength(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   }
				   enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_AUTH, false);

				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "2");
				   if(value!= null) {
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_CA + "2");
				   if(value!= null) {
					 enhprof.setCAId(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_PINTYPE + "2");
				   if(value!= null) {
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(SELECT_MINPINLENGTH + "2");
				   if(value!= null) {
				   	 enhprof.setMinimumPINLength(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));
				   }
				   value = request.getParameter(CHECKBOX_KEYRECOVERABLE + "2");
					if(value != null) {                              
						enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, value.equals(CHECKBOX_VALUE));
					} else {
					  enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, false);
					}
					value = request.getParameter(CHECKBOX_REUSEOLDCERT + "2");
					if(value != null) {                              
						enhprof.setReuseOldCertificate(EnhancedEIDProfile.CERTUSAGE_ENC, value.equals(CHECKBOX_VALUE));
					} else {
						enhprof.setReuseOldCertificate(EnhancedEIDProfile.CERTUSAGE_ENC, false);
					}	
					
				 }

             				 				 
				 if(request.getParameter(BUTTON_SAVE) != null){
				   if(!handler.changeHardTokenProfile(profile,profiledata)){
					   profilemalformed = true;					
				   }
				   includefile=PAGE_HARDTOKENPROFILES;
				 }				 
				 if(request.getParameter(BUTTON_UPLOADENVELOPETEMP) != null){
				   uploadmode = UPLOADMODE_ENVELOPE;
				   includefile=PAGE_UPLOADTEMPLATE;
				 }
				 if(request.getParameter(BUTTON_UPLOADVISUALTEMP) != null){
				   uploadmode =	UPLOADMODE_VISUAL;
				   includefile=PAGE_UPLOADTEMPLATE;
				 }		
				 if(request.getParameter(BUTTON_UPLOADRECEIPTTEMP) != null){
				    uploadmode = UPLOADMODE_RECEIPT;
					includefile=PAGE_UPLOADTEMPLATE;
				 }
				 if(request.getParameter(BUTTON_UPLOADADRESSLABELTEMP) != null){
					uploadmode = UPLOADMODE_ADRESSLABEL;
					includefile=PAGE_UPLOADTEMPLATE;
				}						 
				 
			   }
			   if(request.getParameter(BUTTON_CANCEL) != null){
				  // Don't save changes.
				 includefile=PAGE_HARDTOKENPROFILES;
			   }

			 }
		  }
		}
		
		if( action.equals(ACTION_CHANGE_PROFILETYPE)){
		  this.profilename = request.getParameter(HIDDEN_HARDTOKENPROFILENAME);
		  String value = request.getParameter(SELECT_HARDTOKENTYPE);
		  if(value!=null){        
			int profiletype = Integer.parseInt(value);
			EIDProfile newprofile = null;
			switch(profiletype){          
			  case SwedishEIDProfile.TYPE_SWEDISHEID :
				  newprofile = new SwedishEIDProfile();
				break;
			  case EnhancedEIDProfile.TYPE_ENHANCEDEID:
				  newprofile =  new EnhancedEIDProfile();				      
				break;  	
			  case TurkishEIDProfile.TYPE_TURKISHEID:
				  newprofile =  new TurkishEIDProfile();				      
				break; 
			}  
			if(profiledata != null && profiledata instanceof EIDProfile){
				((EIDProfile) profiledata).clone(newprofile);
				newprofile.reInit();
				profiledata = newprofile;
			}
			
			
		  }

		  includefile=PAGE_HARDTOKENPROFILE;
		}
		if( action.equals(ACTION_UPLOADENVELOPETEMP)){
          if(buttonupload){
          	if(profiledata instanceof IPINEnvelopeSettings){
          	  try{	
                BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
				String filecontent = "";
				String nextline = "";
				while(nextline!=null){
				  nextline = br.readLine();
			 	  if(nextline != null) {				    
				    filecontent += nextline + "\n";
			 	  }
				}                
			    ((IPINEnvelopeSettings) profiledata).setPINEnvelopeData(filecontent);
			    ((IPINEnvelopeSettings) profiledata).setPINEnvelopeTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
			    fileuploadfailed = true;              	 
			  }            	 
			}
          }
		  includefile=PAGE_HARDTOKENPROFILE;
		}
		if( action.equals(ACTION_UPLOADVISUALTEMP)){
			if(profiledata instanceof IVisualLayoutSettings){
			  try{			  
			    BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
			    String filecontent = "";
			    String nextline = "";
			    while(nextline!=null){
				  nextline = br.readLine();
				  if(nextline != null) {				    
				    filecontent += nextline + "\n";
				  }
			    }
			    ((IVisualLayoutSettings) profiledata).setVisualLayoutData(filecontent);
			    ((IVisualLayoutSettings) profiledata).setVisualLayoutTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
				fileuploadfailed = true;              	 
			  }
			}
		  includefile=PAGE_HARDTOKENPROFILE;
		}
		if( action.equals(ACTION_UPLOADRECEIPTTEMP)){
			if(profiledata instanceof IReceiptSettings){
			  try{			  
			    BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
			    String filecontent = "";
			    String nextline = "";
			    while(nextline!=null){
				  nextline = br.readLine();
				  if(nextline != null) {				    
				    filecontent += nextline + "\n";
				  }
			    }
			    ((IReceiptSettings) profiledata).setReceiptData(filecontent);
			    ((IReceiptSettings) profiledata).setReceiptTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
				fileuploadfailed = true;              	 
			  }
			}
		  includefile=PAGE_HARDTOKENPROFILE;
		}
		if( action.equals(ACTION_UPLOADADRESSLABELTEMP)){
			if(profiledata instanceof IAdressLabelSettings){
			  try{			  
			    BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
			    String filecontent = "";
			    String nextline = "";
			    while(nextline!=null){
				  nextline = br.readLine();
				  if(nextline != null) {				    
				    filecontent += nextline + "\n";
				  }
			    }
			    ((IAdressLabelSettings) profiledata).setAdressLabelData(filecontent);
			    ((IAdressLabelSettings) profiledata).setAdressLabelTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
				fileuploadfailed = true;              	 
			  }
			}
		  includefile=PAGE_HARDTOKENPROFILE;
		}		
						
	  }    
  	    
      return includefile;	
    }
    
    public int getProfileType(){    	
      int retval = SwedishEIDProfile.TYPE_SWEDISHEID;
      
      if(profiledata instanceof SwedishEIDProfile) {
        retval = SwedishEIDProfile.TYPE_SWEDISHEID;	
      }
	  if(profiledata instanceof EnhancedEIDProfile) {
      	retval = EnhancedEIDProfile.TYPE_ENHANCEDEID;	
	  }
	  if(profiledata instanceof TurkishEIDProfile) {
	      	retval = TurkishEIDProfile.TYPE_TURKISHEID;
	  }
	  return retval;    	
    }

    

    // Private fields.
    private HardTokenInterfaceBean hardtokenbean;
    private boolean initialized=false;
	public boolean  hardtokenprofileexists       = false;
	public boolean  profilemalformed       = false;
	public boolean  hardtokenprofiledeletefailed = false;
    public boolean  issuperadministrator = false;
    public boolean  fileuploadsuccess = false;
	public boolean  fileuploadfailed  = false;
    public HardTokenProfile profiledata = null;
	public String profilename = null;
	public int uploadmode = 0;
	
}
