<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration
               ,se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.Profile, se.anatom.ejbca.webdist.rainterface.Profiles, se.anatom.ejbca.webdist.rainterface.ProfileExistsException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="ejbcarabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%! // Declarations 
  static final String ACTION                   = "action";
  static final String ACTION_EDIT_PROFILES     = "editprofiles";
  static final String ACTION_EDIT_PROFILE      = "editprofile";

  static final String CHECKBOX_VALUE           = "true";

//  Used in profiles.jsp
  static final String BUTTON_EDIT_PROFILE      = "buttoneditprofile"; 
  static final String BUTTON_DELETE_PROFILE    = "buttondeleteprofile";
//  static final String BUTTON_SET_AS_DEFAULT    = "buttonsetasdefault"; 
  static final String BUTTON_ADD_PROFILE       = "buttonaddprofile"; 
  static final String BUTTON_RENAME_PROFILE    = "buttonrenameprofile";
  static final String BUTTON_CLONE_PROFILE     = "buttoncloneprofile";

  static final String SELECT_PROFILE           = "selectprofile";
  static final String TEXTFIELD_PROFILENAME    = "textfieldprofilename";
  static final String HIDDEN_PROFILENAME       = "hiddenprofilename";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String TEXTFIELD_USERNAME         = "textfieldusername";
  static final String TEXTFIELD_PASSWORD         = "textfieldpassword";
  static final String TEXTFIELD_COMMONNAME       = "textfieldcommonname";
  static final String TEXTFIELD_ORGANIZATIONUNIT = "textfieldorganizationunit";
  static final String TEXTFIELD_ORGANIZATION     = "textfieldorganization";
  static final String TEXTFIELD_LOCALE           = "textfieldlocale";
  static final String TEXTFIELD_STATE            = "textfieldstate";
  static final String TEXTFIELD_COUNTRY          = "textfieldcountry";
  static final String TEXTFIELD_EMAIL            = "textfieldemail";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_TYPEENDUSER                = "checkboxtypeenduser";
  static final String CHECKBOX_TYPERA                     = "checkboxtypera";
  static final String CHECKBOX_TYPERAADMIN                = "checkboxtyperaadmin";
  static final String CHECKBOX_TYPECA                     = "checkboxtypeca";
  static final String CHECKBOX_TYPECAADMIN                = "checkboxtypecaadmin";
  static final String CHECKBOX_TYPEROOTCA                 = "checkboxtyperootca";

  static final String CHECKBOX_REQUIRED_USERNAME          = "checkboxrequiredusername";
  static final String CHECKBOX_REQUIRED_PASSWORD          = "checkboxrequiredpassword";
  static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
  static final String CHECKBOX_REQUIRED_COMMONNAME        = "checkboxrequiredcommonname";
  static final String CHECKBOX_REQUIRED_ORGANIZATIONUNIT  = "checkboxrequiredorganizationunit";
  static final String CHECKBOX_REQUIRED_ORGANIZATION      = "checkboxrequiredorganization";
  static final String CHECKBOX_REQUIRED_LOCALE            = "checkboxrequiredlocale";
  static final String CHECKBOX_REQUIRED_STATE             = "checkboxrequiredstate";
  static final String CHECKBOX_REQUIRED_COUNTRY           = "checkboxrequiredcountry";
  static final String CHECKBOX_REQUIRED_EMAIL             = "checkboxrequiredemail";
  static final String CHECKBOX_REQUIRED_TYPEENDUSER       = "checkboxrequiredtypeenduser";
  static final String CHECKBOX_REQUIRED_TYPERA            = "checkboxrequiredtypera";
  static final String CHECKBOX_REQUIRED_TYPERAADMIN       = "checkboxrequiredtyperaadmin";
  static final String CHECKBOX_REQUIRED_TYPECA            = "checkboxrequiredtypeca";
  static final String CHECKBOX_REQUIRED_TYPECAADMIN       = "checkboxrequiredtypecaadmin";
  static final String CHECKBOX_REQUIRED_TYPEROOTCA        = "checkboxrequiredtyperootca";


  static final String SELECT_TYPE                         = "selecttype";
  String profile = null;
  // Declare Language file.

%>
<% 

  // Initialize environment
  String includefile = null;
  boolean  triedtoeditemptyprofile   = false;
  boolean  triedtodeleteemptyprofile = false;
  boolean  profileexists             = false;

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 

  String THIS_FILENAME            =  globalconfiguration .getRaPath()  + "/profiles/editprofiles.jsp";
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_PROFILES)){
      if( request.getParameter(BUTTON_EDIT_PROFILE) != null){
          // Display  profilepage.jsp
         profile = request.getParameter(SELECT_PROFILE);
         if(profile != null){
           if(!profile.trim().equals("")){
             if(!profile.equals(Profiles.EMPTY_PROFILE)){ 
               includefile="profilepage.jsp"; 
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
          includefile="profilespage.jsp";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_PROFILE) != null) {
          // Delete profile and display profilespage. 
          profile = request.getParameter(SELECT_PROFILE);
          if(profile != null){
            if(!profile.trim().equals("")){
              if(!profile.equals(Profiles.EMPTY_PROFILE)){ 
                ejbcarabean.removeProfile(profile);
              }else{
                triedtodeleteemptyprofile=true;
              }
            }
          }
          includefile="profilespage.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_PROFILE) != null){ 
         // Rename selected profile and display profilespage.
       String newprofilename = request.getParameter(TEXTFIELD_PROFILENAME);
       String oldprofilename = request.getParameter(SELECT_PROFILE);
       if(oldprofilename != null && newprofilename != null){
         if(!newprofilename.trim().equals("") && !oldprofilename.trim().equals("")){
           if(!oldprofilename.equals(Profiles.EMPTY_PROFILE)){ 
             try{
               ejbcarabean.renameProfile(oldprofilename,newprofilename);
             }catch( ProfileExistsException e){
               profileexists=true;
             }
           }else{
              triedtoeditemptyprofile=true;
           }        
         }
       }      
       includefile="profilespage.jsp"; 
      }
      if( request.getParameter(BUTTON_ADD_PROFILE) != null){
         // Add profile and display profilespage.
         profile = request.getParameter(TEXTFIELD_PROFILENAME);
         if(profile != null){
           if(!profile.trim().equals("")){
             try{
               ejbcarabean.addProfile(profile);
             }catch( ProfileExistsException e){
               profileexists=true;
             }
           }      
         }
         includefile="profilespage.jsp"; 
      }
 /*     if( request.getParameter(BUTTON_SET_AS_DEFAULT) != null){
         // Set selected profile as default and display profilespage.
         profile = request.getParameter(SELECT_PROFILE);
         if(profile != null){
           if(!profile.trim().equals("")){
             ejbcarabean.setDefaultProfile(profile);
           }      
         }
         includefile="profilespage.jsp"; 
      }*/
      if( request.getParameter(BUTTON_CLONE_PROFILE) != null){
         // clone profile and display profilespage.
       String newprofilename = request.getParameter(TEXTFIELD_PROFILENAME);
       String oldprofilename = request.getParameter(SELECT_PROFILE);
       if(oldprofilename != null && newprofilename != null){
         if(!newprofilename.trim().equals("") && !oldprofilename.trim().equals("")){
             try{ 
               ejbcarabean.cloneProfile(oldprofilename,newprofilename);
             }catch( ProfileExistsException e){
               profileexists=true;
             }
         }
       }      
          includefile="profilespage.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_PROFILE)){
         // Display edit access rules page.
       profile = request.getParameter(HIDDEN_PROFILENAME);
       if(profile != null){
         if(!profile.trim().equals("")){
           if(request.getParameter(BUTTON_SAVE) != null){
             Profile profiledata = ejbcarabean.getProfile(profile);
             // Save changes.
             String value = request.getParameter(TEXTFIELD_USERNAME);
             String required = null;
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.USERNAME,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_USERNAME);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.USERNAME,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.USERNAME,Profile.FALSE); 
               }
             }
             value = request.getParameter(TEXTFIELD_PASSWORD);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.PASSWORD,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_PASSWORD);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.PASSWORD,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.PASSWORD,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.CLEARTEXTPASSWORD,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.CLEARTEXTPASSWORD,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_CLEARTEXTPASSWORD);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.CLEARTEXTPASSWORD,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.CLEARTEXTPASSWORD,Profile.FALSE); 
               }
             }
             value = request.getParameter(TEXTFIELD_COMMONNAME);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.COMMONNAME,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_COMMONNAME);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.COMMONNAME,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.COMMONNAME,Profile.FALSE); 
               }
             }

             value = request.getParameter(TEXTFIELD_ORGANIZATIONUNIT);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.ORGANIZATIONUNIT,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_ORGANIZATIONUNIT);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.ORGANIZATIONUNIT,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.ORGANIZATIONUNIT,Profile.FALSE); 
               }
             }

             value = request.getParameter(TEXTFIELD_ORGANIZATION);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.ORGANIZATION,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_ORGANIZATION);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.ORGANIZATION,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.ORGANIZATION,Profile.FALSE); 
               }
             }

             value = request.getParameter(TEXTFIELD_LOCALE);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.LOCALE,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_LOCALE);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.LOCALE,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.LOCALE,Profile.FALSE); 
               }
             }

             value = request.getParameter(TEXTFIELD_STATE);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.STATE,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_STATE);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.STATE,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.STATE,Profile.FALSE); 
               }
             }

             value = request.getParameter(TEXTFIELD_COUNTRY);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.COUNTRY,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_COUNTRY);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.COUNTRY,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.COUNTRY,Profile.FALSE); 
               }
             }
             value = request.getParameter(TEXTFIELD_EMAIL);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 profiledata.setValue(Profile.EMAIL,value); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_EMAIL);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.EMAIL,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.EMAIL,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPEENDUSER);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_ENDUSER,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_ENDUSER,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPEENDUSER);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_ENDUSER,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.CLEARTEXTPASSWORD,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPERA);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_RA,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_RA,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPERA);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_RA,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.TYPE_RA,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPERAADMIN);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_RAADMIN,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_RAADMIN,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPERAADMIN);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_RAADMIN,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.TYPE_RAADMIN,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPECA);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_CA,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_CA,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPECA);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_CA,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.TYPE_CA,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPECAADMIN);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_CAADMIN,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_CAADMIN,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPECAADMIN);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_CAADMIN,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.TYPE_CAADMIN,Profile.FALSE); 
               }
             }
             value = request.getParameter(CHECKBOX_TYPEROOTCA);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 profiledata.setValue(Profile.TYPE_ROOTCA,Profile.TRUE);                  
               }
               else{
                 profiledata.setValue(Profile.TYPE_ROOTCA,Profile.FALSE); 
               }
             }
             required = request.getParameter(CHECKBOX_REQUIRED_TYPEROOTCA);
             if(required != null){
               if(required.equals(CHECKBOX_VALUE)){
                 profiledata.setRequired(Profile.TYPE_ROOTCA,Profile.TRUE);                  
               }
               else{
                 profiledata.setRequired(Profile.TYPE_ROOTCA,Profile.FALSE); 
               }
             }
             ejbcarabean.changeProfile(profile,profiledata);
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
           }
             includefile="profilespage.jsp";
         }
      }
    }
  }
  else{ 
    // Display main user group editing page. 
          includefile="profilespage.jsp"; 

  }
 // Include page
  if( includefile.equals("profilepage.jsp")){ %>
   <%@ include file="profilepage.jsp" %>
<%}
  if( includefile.equals("profilespage.jsp")){ %>
   <%@ include file="profilespage.jsp" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
