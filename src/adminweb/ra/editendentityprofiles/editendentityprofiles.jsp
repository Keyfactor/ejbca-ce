<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.SecConst, org.ejbca.core.model.authorization.AuthorizationDeniedException,
                org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, org.ejbca.core.model.ra.raadmin.EndEntityProfile, org.ejbca.core.model.ra.raadmin.UserNotification, org.ejbca.ui.web.admin.rainterface.EndEntityProfileDataHandler, 
                org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException, org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean, org.ejbca.core.model.hardtoken.HardTokenIssuer,org.ejbca.core.model.ra.UserDataConstants, org.ejbca.core.model.ca.crl.RevokedCertInfo,
                org.ejbca.core.model.hardtoken.HardTokenIssuerData, org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper, org.ejbca.util.dn.DnComponents,
                java.io.InputStream, java.io.InputStreamReader,
                java.io.IOException, java.io.BufferedReader, org.apache.commons.fileupload.FileUploadException, org.apache.commons.fileupload.FileItem, org.apache.commons.fileupload.FileUploadBase, org.apache.commons.fileupload.DiskFileUpload,
                org.apache.commons.lang.ArrayUtils, java.text.DateFormat"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="ejbcarabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />

<%! // Declarations 
  static final String ACTION                        = "action";
  static final String ACTION_EDIT_PROFILES          = "editprofiles";
  static final String ACTION_EDIT_PROFILE           = "editprofile";
  static final String ACTION_UPLOADTEMP             = "uploadtemp";

  static final String CHECKBOX_VALUE           = EndEntityProfile.TRUE;

//  Used in profiles.jsp
  static final String BUTTON_EDIT_PROFILE      = "buttoneditprofile"; 
  static final String BUTTON_DELETE_PROFILE    = "buttondeleteprofile";
  static final String BUTTON_ADD_PROFILE       = "buttonaddprofile"; 
  static final String BUTTON_RENAME_PROFILE    = "buttonrenameprofile";
  static final String BUTTON_CLONE_PROFILE     = "buttoncloneprofile";

  static final String SELECT_PROFILE           = "selectprofile";
  static final String TEXTFIELD_PROFILENAME    = "textfieldprofilename";
  static final String HIDDEN_PROFILENAME       = "hiddenprofilename";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
  static final String BUTTON_UPLOADTEMPLATE    = "buttonuploadtemplate";
  static final String BUTTON_UPLOADFILE        = "buttonuploadfile";
 
  static final String BUTTON_ADD_NOTIFICATION    = "buttonaddnotification";
  static final String BUTTON_DELETEALL_NOTIFICATION = "buttondeleteallnotification";
  static final String BUTTON_DELETE_NOTIFICATION = "buttondeleltenotification";
 
  static final String TEXTFIELD_USERNAME             = "textfieldusername";
  static final String TEXTFIELD_PASSWORD             = "textfieldpassword";
  static final String TEXTFIELD_SUBJECTDN            = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME       = "textfieldsubjectaltname";
  static final String TEXTFIELD_SUBJECTDIRATTR       = "textfieldsubjectdirattr";
  static final String TEXTFIELD_EMAIL                = "textfieldemail";
  static final String TEXTFIELD_NOTIFICATIONSENDER   = "textfieldnotificationsender";
  static final String TEXTFIELD_NOTIFICATIONRCPT     = "textfieldnotificationrcpt";
  static final String TEXTFIELD_NOTIFICATIONSUBJECT  = "textfieldnotificationsubject";
  static final String SELECT_NOTIFICATIONEVENTS      = "selectnotificationevents";
  static final String TEXTFIELD_STARTTIME            = "textfieldstarttime";
  static final String TEXTFIELD_ENDTIME              = "textfieldendtime";
  static final String TEXTFIELD_MAXFAILEDLOGINS	     = "textfieldmaxfailedlogins";
 
  static final String TEXTAREA_NOTIFICATIONMESSAGE  = "textareanotificationmessage";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
  static final String CHECKBOX_REUSECERTIFICATE           = "checkboxreusecertificate";
  static final String CHECKBOX_REVERSEFIELDCHECKS         = "checkboxreversefieldchecks";
  static final String CHECKBOX_CARDNUMBER                 = "checkboxcardnumber";
  static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";
  static final String CHECKBOX_PRINTING                   = "checkboxprinting";
  static final String CHECKBOX_USE_STARTTIME              = "checkboxsusetarttime";
  static final String CHECKBOX_REQUIRED_STARTTIME         = "checkboxrelativestarttime";
  static final String CHECKBOX_MODIFYABLE_STARTTIME       = "checkboxmodifyablestarttime";
  static final String CHECKBOX_USE_ENDTIME                = "checkboxuseendtime";
  static final String CHECKBOX_REQUIRED_ENDTIME           = "checkboxrelativeendtime";
  static final String CHECKBOX_MODIFYABLE_ENDTIME         = "checkboxmodifyableendtime";
  static final String CHECKBOX_ALLOW_MERGEDN_WEBSERVICES = "checkboxallowmergednwebservices";
  
  static final String CHECKBOX_ENFORCE_UNIQUE_SERIAL_NUMBER = "checkboxenforceuniqueserialnumber";
  
  
  static final String CHECKBOX_REQUIRED_PASSWORD          = "checkboxrequiredpassword";
  static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
  static final String CHECKBOX_REQUIRED_SUBJECTDN         = "checkboxrequiredsubjectdn";
  static final String CHECKBOX_REQUIRED_SUBJECTALTNAME    = "checkboxrequiredsubjectaltname";
  static final String CHECKBOX_REQUIRED_SUBJECTDIRATTR    = "checkboxrequiredsubjectdirattr";
  static final String CHECKBOX_REQUIRED_EMAIL             = "checkboxrequiredemail";
  static final String CHECKBOX_REQUIRED_CARDNUMBER        = "checkboxrequiredcardnumber";
  static final String CHECKBOX_REQUIRED_SENDNOTIFICATION  = "checkboxrequiredsendnotification";
  static final String CHECKBOX_REQUIRED_KEYRECOVERABLE    = "checkboxrequiredkeyrecoverable";
  static final String CHECKBOX_REQUIRED_PRINTING          = "checkboxrequiredprinting";
  static final String CHECKBOX_REQUIRED_MAXFAILEDLOGINS	  = "checkboxrequiredmaxfailedlogins";


  static final String CHECKBOX_MODIFYABLE_PASSWORD          = "checkboxmodifyablepassword";
  static final String CHECKBOX_MODIFYABLE_SUBJECTDN         = "checkboxmodifyablesubjectdn";
  static final String CHECKBOX_MODIFYABLE_SUBJECTALTNAME    = "checkboxmodifyablesubjectaltname";
  static final String CHECKBOX_MODIFYABLE_SUBJECTDIRATTR    = "checkboxmodifyablesubjectdirattr";
  static final String CHECKBOX_MODIFYABLE_EMAIL             = "checkboxmodifyableemail";
  static final String CHECKBOX_MODIFYABLE_ISSUANCEREVOCATIONREASON = "checkboxmodifyableissuancerevocationreason";
  static final String CHECKBOX_MODIFYABLE_MAXFAILEDLOGINS	= "checkboxmodifyablemaxfailedlogins";

  static final String CHECKBOX_USE_CARDNUMBER        = "checkboxusecardnumber";
  static final String CHECKBOX_USE_PASSWORD          = "checkboxusepassword";
  static final String CHECKBOX_USE_CLEARTEXTPASSWORD = "checkboxusecleartextpassword";
  static final String CHECKBOX_USE_SUBJECTDN         = "checkboxusesubjectdn";
  static final String CHECKBOX_USE_SUBJECTALTNAME    = "checkboxusesubjectaltname";
  static final String CHECKBOX_USE_EMAIL             = "checkboxuseemail";
  static final String CHECKBOX_USE_KEYRECOVERABLE    = "checkboxusekeyrecoverable";
  static final String CHECKBOX_USE_SENDNOTIFICATION  = "checkboxusesendnotification";
  static final String CHECKBOX_USE_HARDTOKENISSUERS  = "checkboxusehardtokenissuers";
  static final String CHECKBOX_USE_PRINTING          = "checkboxuseprinting";
  static final String CHECKBOX_USE_ALLOWEDRQUESTS    = "checkboxuseallowedrequests";
  static final String CHECKBOX_USE_ISSUANCEREVOCATIONREASON = "checkboxuseissuancerevocationreason";
  static final String CHECKBOX_USE_MAXFAILEDLOGINS	 = "checkboxusemaxfailedlogins";
  
  static final String RADIO_MAXFAILEDLOGINS		  		  = "radiomaxfailedlogins";
  static final String RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED = "unlimited";
  static final String RADIO_MAXFAILEDLOGINS_VAL_SPECIFIED = "specified";
  
  static final String SELECT_AUTOPASSWORDTYPE               = "selectautopasswordtype";
  static final String SELECT_AUTOPASSWORDLENGTH             = "selectautopasswordlength";

  static final String SELECT_ISSUANCEREVOCATIONREASON       = "selectissuancerevocationreason";
  
  static final String SELECT_DEFAULTCERTPROFILE             = "selectdefaultcertprofile";
  static final String SELECT_AVAILABLECERTPROFILES          = "selectavailablecertprofiles";

  static final String SELECT_DEFAULTTOKENTYPE               = "selectdefaulttokentype";
  static final String SELECT_AVAILABLETOKENTYPES            = "selectavailabletokentypes";


  static final String SELECT_DEFAULTCA                      = "selectdefaultca";
  static final String SELECT_AVAILABLECAS                   = "selectavailablecas";

  static final String SELECT_DEFAULTHARDTOKENISSUER         = "selectdefaulthardtokenissuer";
  static final String SELECT_AVAILABLEHARDTOKENISSUERS      = "selectavailablehardtokenissuers";

  static final String SELECT_PRINTINGPRINTERNAME            = "selectprinteringprintername";
  static final String SELECT_PRINTINGCOPIES                 = "selectprinteringcopies";

  static final String SELECT_ALLOWEDREQUESTS                = "selectallowedrequests";

  static final String SELECT_ADDSUBJECTDN                   = "selectaddsubjectdn";
  static final String BUTTON_DELETESUBJECTDN                = "buttondeletesubjectdn";
  static final String BUTTON_ADDSUBJECTDN                   = "buttonaddsubjectdn";
  static final String CHECKBOX_SELECTSUBJECTDN              = "checkboxselectsubjectdn";
  static final String SELECT_ADDSUBJECTALTNAME              = "selectaddsubjectaltname";
  static final String BUTTON_DELETESUBJECTALTNAME           = "buttondeletesubjectaltname";
  static final String BUTTON_ADDSUBJECTALTNAME              = "buttonaddsubjectaltname";
  static final String CHECKBOX_SELECTSUBJECTALTNAME         = "checkboxselectsubjectaltname";

  static final String SELECT_ADDSUBJECTDIRATTR              = "selectaddsubjectdirattr";
  static final String BUTTON_DELETESUBJECTDIRATTR           = "buttondeletesubjectdirattr";
  static final String BUTTON_ADDSUBJECTDIRATTR              = "buttonaddsubjectdirattr";
  static final String CHECKBOX_SELECTSUBJECTDIRATTR         = "checkboxselectsubjectdirattr";
  static final String SELECT_TYPE                         = "selecttype";
  
  public static final String FILE_TEMPLATE             = "filetemplate";
  String profile = null;
  // Declare Language file.

%>
<% 

  // Initialize environment
  String includefile = "endentityprofilespage.jspf";
  boolean  triedtoeditemptyprofile   = false;
  boolean  triedtodeleteemptyprofile = false;
  boolean  profileexists             = false;
  boolean  profiledeletefailed       = false;
  boolean  cannotcloneempty          = false;
  boolean  fileuploadfailed          = false;
  boolean  fileuploadsuccess         = false;
  boolean  buttonupload             = false;
  
  String action = null;
  
  InputStream templateData = null;
  String templateFilename = null;

  int numberofsubjectdnfields=0;
  int numberofsubjectaltnamefields=0;
  int numberofsubjectdirattrfields=0;
  String value=null;
  EndEntityProfile profiledata=null;
  int[] fielddata = null;

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/ra_functionality/edit_end_entity_profiles"); 
                                            ejbcarabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(request, ejbcawebbean);
                                            tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME            =  globalconfiguration .getRaPath()  + "/editendentityprofiles/editendentityprofiles.jsp";
  
  boolean issuperadministrator = false;
  try{
    issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(AuthorizationDeniedException ade){}   

%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 
  RequestHelper.setDefaultCharacterEncoding(request);



  if(FileUploadBase.isMultipartContent(request)){
  	try{     	  	
	  DiskFileUpload upload = new DiskFileUpload();
	  upload.setSizeMax(2000000);                   
	  upload.setSizeThreshold(1999999);
	  List /* FileItem */ items = upload.parseRequest(request);     

	  Iterator iter = items.iterator();
	  while (iter.hasNext()) {     
	  FileItem item = (FileItem) iter.next();

	    if (item.isFormField()) {         
		  if(item.getFieldName().equals(ACTION))
		    action = item.getString(); 
		  if(item.getFieldName().equals(BUTTON_CANCEL)) {
		      // do nothing
          }
		  if(item.getFieldName().equals(BUTTON_UPLOADFILE)){
			 buttonupload = true;
		  }
	    }else{         
		  templateData = item.getInputStream();
		  templateFilename = item.getName(); 
	    }
	  }
  	}catch(IOException e){
  	  fileuploadfailed = true;
	  includefile="endentityprofilepage.jspf";	  
  	}catch(FileUploadException e){
	  fileuploadfailed = true;	  
	  includefile="endentityprofilepage.jspf";
    }
  }else{
		action = request.getParameter(ACTION);
  }

  if( action != null){
    if( action.equals(ACTION_EDIT_PROFILES)){
      if( request.getParameter(BUTTON_EDIT_PROFILE) != null){
          // Display  profilepage.jspf
         profile = request.getParameter(SELECT_PROFILE);
         if(profile != null){
           if(!profile.trim().equals("")){
             if(!profile.equals(EndEntityProfileDataHandler.EMPTY_PROFILE)){ 
               ejbcarabean.setTemporaryEndEntityProfile(null);
               includefile="endentityprofilepage.jspf"; 
             }else{
                triedtoeditemptyprofile=true;
                profile= null;
             }
           } 
           else{ 
            profile= null;
          } 
        }
        if(profile == null){   
          includefile="endentityprofilespage.jspf";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_PROFILE) != null) {
          // Delete profile and display profilespage. 
          profile = request.getParameter(SELECT_PROFILE);
          if(profile != null){
            if(!profile.trim().equals("")){
              if(!profile.equals(EndEntityProfileDataHandler.EMPTY_PROFILE)){ 
                profiledeletefailed = !ejbcarabean.removeEndEntityProfile(profile); 
              }else{
                triedtodeleteemptyprofile=true;
              }
            }
          }
          includefile="endentityprofilespage.jspf";             
      }
      if( request.getParameter(BUTTON_RENAME_PROFILE) != null){ 
         // Rename selected profile and display profilespage.
       String newprofilename = request.getParameter(TEXTFIELD_PROFILENAME);
       String oldprofilename = request.getParameter(SELECT_PROFILE);
       if(oldprofilename != null && newprofilename != null){
         if(!newprofilename.trim().equals("") && !oldprofilename.trim().equals("")){
           if(!oldprofilename.equals(EndEntityProfileDataHandler.EMPTY_PROFILE)){ 
             try{
               ejbcarabean.renameEndEntityProfile(oldprofilename.trim(),newprofilename.trim());
             }catch( EndEntityProfileExistsException e){
               profileexists=true;
             }
           }else{
              triedtoeditemptyprofile=true;
           }        
         }
       }      
       includefile="endentityprofilespage.jspf"; 
      }
      if( request.getParameter(BUTTON_ADD_PROFILE) != null){
         // Add profile and display profilespage.
         profile = request.getParameter(TEXTFIELD_PROFILENAME);
         if(profile != null){
           if(!profile.trim().equals("")){
             try{
               ejbcarabean.addEndEntityProfile(profile.trim());
             }catch( EndEntityProfileExistsException e){
               profileexists=true;
             }
           }      
         }
         includefile="endentityprofilespage.jspf"; 
      }
      if( request.getParameter(BUTTON_CLONE_PROFILE) != null){
         // clone profile and display profilespage.
       String newprofilename = request.getParameter(TEXTFIELD_PROFILENAME);
       String oldprofilename = request.getParameter(SELECT_PROFILE);
       if(oldprofilename != null && newprofilename != null){
         if(!newprofilename.trim().equals("") && !oldprofilename.trim().equals("")){
             if(!oldprofilename.equals(EndEntityProfileDataHandler.EMPTY_PROFILE)){ 
               try{ 
                 ejbcarabean.cloneEndEntityProfile(oldprofilename.trim(),newprofilename.trim());
               }catch( EndEntityProfileExistsException e){
                 profileexists=true;
               }
             }else{
                cannotcloneempty = true;                
             }
         }
       }      
          includefile="endentityprofilespage.jspf"; 
      }
    }
    
    if( action.equals(ACTION_EDIT_PROFILE)){
         // Display edit access rules page.
       profile = request.getParameter(HIDDEN_PROFILENAME);
       if(profile != null){
         if(!profile.trim().equals("")){
             profiledata = ejbcarabean.getTemporaryEndEntityProfile();
             if(profiledata == null){
               profiledata = ejbcarabean.getEndEntityProfile(profile);
             }
             // Save changes.
             profiledata.setAllowMergeDnWebServices(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_ALLOW_MERGEDN_WEBSERVICES)));
             
             profiledata.setValue(EndEntityProfile.USERNAME , 0, request.getParameter(TEXTFIELD_USERNAME));
             profiledata.setRequired(EndEntityProfile.USERNAME, 0 ,true); // Always required
             profiledata.setModifyable(EndEntityProfile.USERNAME, 0 ,true); // Always modifyable

             profiledata.setValue(EndEntityProfile.PASSWORD, 0  ,request.getParameter(TEXTFIELD_PASSWORD));
             profiledata.setUse(EndEntityProfile.PASSWORD, 0  , !ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_PASSWORD)));
             profiledata.setRequired(EndEntityProfile.PASSWORD, 0  ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_PASSWORD)));
             profiledata.setModifyable(EndEntityProfile.PASSWORD, 0 , true);
 
             profiledata.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0  ,request.getParameter(CHECKBOX_CLEARTEXTPASSWORD));
             profiledata.setRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_CLEARTEXTPASSWORD))); 
             profiledata.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_CLEARTEXTPASSWORD))); 
             
             profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDTYPE, 0, request.getParameter(SELECT_AUTOPASSWORDTYPE));
             profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDLENGTH, 0, request.getParameter(SELECT_AUTOPASSWORDLENGTH));
             
             int nValue = -1;
             try {
            	 nValue = Integer.parseInt(request.getParameter(TEXTFIELD_MAXFAILEDLOGINS));
             } catch(NumberFormatException ignored) {}
             value = request.getParameter(RADIO_MAXFAILEDLOGINS);
             if(RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED.equals(value) || nValue < -1) {
            	value = "-1";
             } else {
             	value = Integer.toString(nValue);
             }
             profiledata.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, value);
             profiledata.setRequired(EndEntityProfile.MAXFAILEDLOGINS, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_MAXFAILEDLOGINS)));
             profiledata.setUse(EndEntityProfile.MAXFAILEDLOGINS, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_MAXFAILEDLOGINS)));
             profiledata.setModifyable(EndEntityProfile.MAXFAILEDLOGINS, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_MAXFAILEDLOGINS)));
             
             profiledata.setReverseFieldChecks(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REVERSEFIELDCHECKS)));
             profiledata.setEnforceUniqueSerialNumber(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_ENFORCE_UNIQUE_SERIAL_NUMBER)));
             
             numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();

             for(int i=0; i < numberofsubjectdnfields; i ++){
                fielddata = profiledata.getSubjectDNFieldsInOrder(i);
                profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                        ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDN + i)));
                if( !EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAIL) ) {
                    profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                                         request.getParameter(TEXTFIELD_SUBJECTDN + i));                
                	profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                	                          ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTDN + i)));
                } else {
                    profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                                         request.getParameter(TEXTFIELD_EMAIL));                
                    profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                                              ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_EMAIL)));
                }
             }

             numberofsubjectaltnamefields = profiledata.getSubjectAltNameFieldOrderLength();

             for(int i=0; i < numberofsubjectaltnamefields; i ++){
                fielddata = profiledata.getSubjectAltNameFieldsInOrder(i);
	        	if ( EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME) ) {
					profiledata.setUse( fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER],
						ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SUBJECTALTNAME + i)) );
	        	}
                profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , request.getParameter(TEXTFIELD_SUBJECTALTNAME + i));                
                profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                        ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTALTNAME + i)));
                profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                        ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTALTNAME + i)));
             } 
            
             numberofsubjectdirattrfields = profiledata.getSubjectDirAttrFieldOrderLength();

             for(int i=0; i < numberofsubjectdirattrfields; i ++){
                fielddata = profiledata.getSubjectDirAttrFieldsInOrder(i);
                profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , request.getParameter(TEXTFIELD_SUBJECTDIRATTR + i));                
                profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                        ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDIRATTR + i)));
                profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                        ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTDIRATTR + i)));
             } 

             profiledata.setValue(EndEntityProfile.EMAIL, 0,request.getParameter(TEXTFIELD_EMAIL));
             profiledata.setRequired(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_EMAIL)));
             profiledata.setModifyable(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_EMAIL))); 
             profiledata.setUse(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_EMAIL))); 
 
             if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_KEYRECOVERABLE)))
               profiledata.setValue(EndEntityProfile.KEYRECOVERABLE, 0 ,EndEntityProfile.TRUE);
             else
               profiledata.setValue(EndEntityProfile.KEYRECOVERABLE, 0 ,EndEntityProfile.FALSE);
             profiledata.setRequired(EndEntityProfile.KEYRECOVERABLE, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_KEYRECOVERABLE)));
             profiledata.setUse(EndEntityProfile.KEYRECOVERABLE, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_KEYRECOVERABLE)));
             
             profiledata.setReUseKeyRevoceredCertificate(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REUSECERTIFICATE)));
             
             if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_CARDNUMBER)))
                 profiledata.setValue(EndEntityProfile.CARDNUMBER, 0 ,EndEntityProfile.TRUE);
               else
                 profiledata.setValue(EndEntityProfile.CARDNUMBER, 0 ,EndEntityProfile.FALSE);
               profiledata.setRequired(EndEntityProfile.CARDNUMBER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_CARDNUMBER)));
               profiledata.setUse(EndEntityProfile.CARDNUMBER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_CARDNUMBER))); 

             
             if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SENDNOTIFICATION)))
               profiledata.setValue(EndEntityProfile.SENDNOTIFICATION, 0 ,EndEntityProfile.TRUE);
             else
               profiledata.setValue(EndEntityProfile.SENDNOTIFICATION, 0 ,EndEntityProfile.FALSE);
             profiledata.setRequired(EndEntityProfile.SENDNOTIFICATION, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SENDNOTIFICATION)));
             profiledata.setUse(EndEntityProfile.SENDNOTIFICATION, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SENDNOTIFICATION))); 

             String issrevreason =  request.getParameter(SELECT_ISSUANCEREVOCATIONREASON);
             if(issrevreason != null)
                 profiledata.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,issrevreason);
               else
                 profiledata.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,""+RevokedCertInfo.NOT_REVOKED);
             profiledata.setModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_ISSUANCEREVOCATIONREASON)));
             profiledata.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_ISSUANCEREVOCATIONREASON))); 
             profiledata.setRequired(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,true);

             String defaultcertprof =  request.getParameter(SELECT_DEFAULTCERTPROFILE);
             profiledata.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0,defaultcertprof);
             profiledata.setRequired(EndEntityProfile.DEFAULTCERTPROFILE, 0,true);

             String[] values = request.getParameterValues(SELECT_AVAILABLECERTPROFILES);
 
             if(defaultcertprof != null){
               String availablecert =defaultcertprof;
               if(values!= null){
                 for(int i=0; i< values.length; i++){
                     if(!values[i].equals(defaultcertprof))
                       availablecert += EndEntityProfile.SPLITCHAR + values[i];                      
                 }
               } 
               
               profiledata.setValue(EndEntityProfile.AVAILCERTPROFILES, 0,availablecert);
               profiledata.setRequired(EndEntityProfile.AVAILCERTPROFILES, 0,true);    
             }

             String defaultca =  request.getParameter(SELECT_DEFAULTCA);
             profiledata.setValue(EndEntityProfile.DEFAULTCA, 0,defaultca);
             profiledata.setRequired(EndEntityProfile.DEFAULTCA, 0,true);

             values = request.getParameterValues(SELECT_AVAILABLECAS);
 
             if(defaultca != null){
               String availablecas = defaultca;
               if(values!= null){
                 for(int i=0; i< values.length; i++){
                     if(!values[i].equals(defaultca))
                       availablecas += EndEntityProfile.SPLITCHAR + values[i];                      
                 }
               } 
               
               profiledata.setValue(EndEntityProfile.AVAILCAS, 0,availablecas);
               profiledata.setRequired(EndEntityProfile.AVAILCAS, 0,true);    
             }


             String defaulttokentype =  request.getParameter(SELECT_DEFAULTTOKENTYPE);
             profiledata.setValue(EndEntityProfile.DEFKEYSTORE, 0,defaulttokentype);
             profiledata.setRequired(EndEntityProfile.DEFKEYSTORE, 0,true);

             values = request.getParameterValues(SELECT_AVAILABLETOKENTYPES);
 
             if(defaulttokentype != null){
               String availabletokentypes =defaulttokentype;
               if(values!= null){
                 for(int i=0; i< values.length; i++){
                     if(!values[i].equals(defaulttokentype))
                       availabletokentypes += EndEntityProfile.SPLITCHAR + values[i];                      
                 }
               } 
               profiledata.setValue(EndEntityProfile.AVAILKEYSTORE, 0, availabletokentypes);
               profiledata.setRequired(EndEntityProfile.AVAILKEYSTORE, 0, true);    
             }

             profiledata.setUse(EndEntityProfile.AVAILTOKENISSUER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_HARDTOKENISSUERS))); 

             String defaulthardtokenissuer =  request.getParameter(SELECT_DEFAULTHARDTOKENISSUER);
             profiledata.setValue(EndEntityProfile.DEFAULTTOKENISSUER, 0,defaulthardtokenissuer);
             profiledata.setRequired(EndEntityProfile.DEFAULTTOKENISSUER, 0,true);

             values = request.getParameterValues(SELECT_AVAILABLEHARDTOKENISSUERS);
 
             if(defaulthardtokenissuer != null){
               String availablehardtokenissuers =defaulthardtokenissuer;
               if(values!= null){
                 for(int i=0; i< values.length; i++){
                     if(!values[i].equals(defaulthardtokenissuer))
                       availablehardtokenissuers += EndEntityProfile.SPLITCHAR + values[i];                      
                 }
               } 
               profiledata.setValue(EndEntityProfile.AVAILTOKENISSUER, 0, availablehardtokenissuers);
               profiledata.setRequired(EndEntityProfile.AVAILTOKENISSUER, 0, true);    
             }
             
             String sender = request.getParameter(TEXTFIELD_NOTIFICATIONSENDER);
             if ( (sender != null) && (sender.length() > 0) ) {
                 UserNotification not = new UserNotification();
                 not.setNotificationSender(sender);
                 not.setNotificationSubject(request.getParameter(TEXTFIELD_NOTIFICATIONSUBJECT));
                 not.setNotificationMessage(request.getParameter(TEXTAREA_NOTIFICATIONMESSAGE));
                 String rcpt = request.getParameter(TEXTFIELD_NOTIFICATIONRCPT);
                 if ( (rcpt == null) || (rcpt.length() == 0) ) {
                     // Default value if nothing is entered is users email address
                     rcpt = UserNotification.RCPT_USER;
                 }
                 not.setNotificationRecipient(rcpt);
                 String[] val1 = request.getParameterValues(SELECT_NOTIFICATIONEVENTS);
                 String events = null;
     			 for(int i = 0; i < val1.length; i++) {
     			    if (events == null) {
     			       events = val1[i];
     			    } else {
                       events = events + ";"+val1[i];
                    }
                 }
                 not.setNotificationEvents(events);
                 profiledata.addUserNotification(not);
             }
             
             value = request.getParameter(CHECKBOX_USE_PRINTING);
             if(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)){
            	 profiledata.setUsePrinting(true);
            	 
                 value = request.getParameter(CHECKBOX_PRINTING);
                 if(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)){
                    profiledata.setPrintingDefault(true);
                 }else{
                     profiledata.setPrintingDefault(false);                	 
                 }
                 value = request.getParameter(CHECKBOX_REQUIRED_PRINTING);
                 if(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)){
                	 profiledata.setPrintingRequired(true);
                 }else{
                	 profiledata.setPrintingRequired(false);                	 
                 }            	 
            	 
                 value = request.getParameter(SELECT_PRINTINGCOPIES);
                 if(value != null){
                   profiledata.setPrintedCopies(Integer.parseInt(value));
                 }
                 value = request.getParameter(SELECT_PRINTINGPRINTERNAME);
                 if(value != null){
                   profiledata.setPrinterName(value);
                 } 
                 
             }else{
            	 profiledata.setUsePrinting(false);
            	 profiledata.setPrintingDefault(false);
            	 profiledata.setPrintingRequired(false);
            	 profiledata.setPrintedCopies(1);
            	 profiledata.setPrinterName("");
            	 profiledata.setPrinterSVGData("");
            	 profiledata.setPrinterSVGFileName("");            	
             }
             
				value = request.getParameter(CHECKBOX_USE_STARTTIME);
				if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
					value = request.getParameter(TEXTFIELD_STARTTIME);
					if( value != null ) {
						profiledata.setValue(EndEntityProfile.STARTTIME, 0, value);
					} else {
						profiledata.setValue(EndEntityProfile.STARTTIME, 0, "");
					}
					profiledata.setUse(EndEntityProfile.STARTTIME, 0, true);
					//profiledata.setRequired(EndEntityProfile.STARTTIME, 0, true);
					value = request.getParameter(CHECKBOX_MODIFYABLE_STARTTIME);
					if ( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
						profiledata.setModifyable(EndEntityProfile.STARTTIME, 0, true);
					} else {
						profiledata.setModifyable(EndEntityProfile.STARTTIME, 0, false);
					}
				} else {
					profiledata.setValue(EndEntityProfile.STARTTIME, 0, "");
					profiledata.setUse(EndEntityProfile.STARTTIME, 0, false);
				}
				value = request.getParameter(CHECKBOX_USE_ENDTIME);
				if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
					value = request.getParameter(TEXTFIELD_ENDTIME);
					if( value != null ) {
						profiledata.setValue(EndEntityProfile.ENDTIME, 0, value);
					} else {
						profiledata.setValue(EndEntityProfile.ENDTIME, 0, "");
					}
					profiledata.setUse(EndEntityProfile.ENDTIME, 0, true);
					//profiledata.setRequired(EndEntityProfile.ENDTIME, 0, true);
					value = request.getParameter(CHECKBOX_MODIFYABLE_ENDTIME);
					if ( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
						profiledata.setModifyable(EndEntityProfile.ENDTIME, 0, true);
					} else {
						profiledata.setModifyable(EndEntityProfile.ENDTIME, 0, false);
					}
				} else {
					profiledata.setValue(EndEntityProfile.ENDTIME, 0, "");
					profiledata.setUse(EndEntityProfile.ENDTIME, 0, false);
				}

				value = request.getParameter(CHECKBOX_USE_ALLOWEDRQUESTS);
				if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
					value = request.getParameter(SELECT_ALLOWEDREQUESTS);
					if( value != null ) {
						profiledata.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, value);
					}
					profiledata.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
				} else {
					profiledata.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
				}

             if(request.getParameter(BUTTON_DELETESUBJECTDN) != null){  
               numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();
               int pointer = 0;
               for(int i=0; i < numberofsubjectdnfields; i++){
                 if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTDN + i))){
                   fielddata = profiledata.getSubjectDNFieldsInOrder(pointer);  
                   profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                 }
                 else
                   pointer++;
               }                          
             }
             if(request.getParameter(BUTTON_ADDSUBJECTDN) != null){             
               value = request.getParameter(SELECT_ADDSUBJECTDN);
               if(value!=null){
                 profiledata.addField(value);             
               }                   
             }
             if(request.getParameter(BUTTON_DELETESUBJECTALTNAME) != null){             
               numberofsubjectaltnamefields = profiledata.getSubjectAltNameFieldOrderLength();
               int pointer = 0;
               for(int i=0; i < numberofsubjectaltnamefields; i++){
                 if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTALTNAME+i))){
                   fielddata = profiledata.getSubjectAltNameFieldsInOrder(pointer);  
                   profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                 }
                 else
                   pointer++;
               }             
             }
             if(request.getParameter(BUTTON_ADDSUBJECTALTNAME) != null){             
               value = request.getParameter(SELECT_ADDSUBJECTALTNAME);
               if(value!=null){
                 profiledata.addField(value);                
               }                       
             }
             
             if(request.getParameter(BUTTON_DELETESUBJECTDIRATTR) != null){             
               numberofsubjectdirattrfields = profiledata.getSubjectDirAttrFieldOrderLength();
               int pointer = 0;
               for(int i=0; i < numberofsubjectdirattrfields; i++){
                 if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTDIRATTR+i))){
                   fielddata = profiledata.getSubjectDirAttrFieldsInOrder(pointer);  
                   profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                 }
                 else
                   pointer++;
               }             
             }
             if(request.getParameter(BUTTON_ADDSUBJECTDIRATTR) != null){             
               value = request.getParameter(SELECT_ADDSUBJECTDIRATTR);
               if(value!=null){
                 profiledata.addField(value);                
               }                       
             }
             
             includefile="endentityprofilepage.jspf";
             ejbcarabean.setTemporaryEndEntityProfile(profiledata);
           
             if(request.getParameter(BUTTON_SAVE) != null){             
               ejbcarabean.changeEndEntityProfile(profile,profiledata);
               ejbcarabean.setTemporaryEndEntityProfile(null);
               includefile="endentityprofilespage.jspf";  
             }
             /*
              * Add user notice.
              */
             if(request.getParameter(BUTTON_ADD_NOTIFICATION) != null) {
                 ejbcarabean.setTemporaryEndEntityProfile(profiledata);
                 includefile = "endentityprofilepage.jspf";
             }
             /*
              * Remove all user notices.
              */
             if(request.getParameter(BUTTON_DELETEALL_NOTIFICATION) != null) {
                 ArrayList emptynot = new ArrayList();
                 profiledata.setUserNotifications(emptynot);
                 ejbcarabean.setTemporaryEndEntityProfile(profiledata);
                 includefile = "endentityprofilepage.jspf";
             }
             /*
              * Remove user notice.
              */
             if (profiledata.getUserNotifications() != null) {
                 boolean removed = false;
                 for(int i = 0; i < profiledata.getUserNotifications().size(); i++) {
                     value = request.getParameter(BUTTON_DELETE_NOTIFICATION + i);
                     if(value != null) {
                         String s = request.getParameter(TEXTFIELD_NOTIFICATIONSENDER + i);
                         String r = request.getParameter(TEXTFIELD_NOTIFICATIONRCPT + i);
                         String sub = request.getParameter(TEXTFIELD_NOTIFICATIONSUBJECT + i);
                         String msg = request.getParameter(TEXTAREA_NOTIFICATIONMESSAGE + i);
                         String[] val = request.getParameterValues(SELECT_NOTIFICATIONEVENTS + i);
                         String events = null;
     			         for(int j = 0; j < val.length; j++) {
     			            if (events == null) {
     			               events = val[j];
     			            } else {
                               events = events + ";"+val[j];
                            }
                         }
                         UserNotification not = new UserNotification(s, r, sub, msg, events);
                         profiledata.removeUserNotification(not);
                         ejbcarabean.setTemporaryEndEntityProfile(profiledata);
                         removed = true;
                     }
                 }         
                 if (removed) {
                   includefile = "endentityprofilepage.jspf";
                 }
             }
             
			 if(request.getParameter(BUTTON_UPLOADTEMPLATE) != null){
				   includefile="uploadtemplate.jspf";
		      }
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
             ejbcarabean.setTemporaryEndEntityProfile(null);
             includefile="endentityprofilespage.jspf";
           }
      }
    }
	if( action.equals(ACTION_UPLOADTEMP)){
		if(buttonupload){
		  try{			  
		    BufferedReader br = new BufferedReader(new InputStreamReader(templateData,"UTF8"));
		    String filecontent = "";
		    String nextline = "";
		    while(nextline!=null){
			  nextline = br.readLine();
			  if(nextline != null)				    
			    filecontent += nextline + "\n";
		    }
		    if(filecontent.equals("")){
		    	fileuploadfailed = true;  
		    }else{
		      profiledata = ejbcarabean.getTemporaryEndEntityProfile();
		      profiledata.setPrinterSVGData(filecontent);
		      profiledata.setPrinterSVGFileName(templateFilename);
		      ejbcarabean.setTemporaryEndEntityProfile(profiledata);
  		      fileuploadsuccess = true;
		    }
		  }catch(IOException ioe){
			fileuploadfailed = true;              	 
		  }
		}
	   includefile="endentityprofilepage.jspf";  
	}
  }
  
 // Include page
  if( includefile.equals("endentityprofilepage.jspf")){ %>
   <%@ include file="endentityprofilepage.jspf" %>
<%}
  if( includefile.equals("endentityprofilespage.jspf")){ %>
   <%@ include file="endentityprofilespage.jspf" %> 
<%}  
  if( includefile.equals("uploadtemplate.jspf")){ %>
   <%@ include file="uploadtemplate.jspf" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
