<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%
    response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
%>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst
               ,org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean, org.ejbca.core.model.hardtoken.HardTokenIssuer,org.ejbca.core.model.hardtoken.HardTokenIssuerInformation,org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException,org.ejbca.core.model.hardtoken.HardTokenIssuerDoesntExistsException,org.cesecore.roles.RoleData,org.ejbca.ui.web.CertificateView,org.ejbca.core.model.authorization.AccessRulesConstants"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%!// Declarations 
  static final String ACTION                        = "action";
  static final String ACTION_EDIT_ISSUERS           = "editissuers";
  static final String ACTION_EDIT_ISSUER            = "editissuer";

  static final String CHECKBOX_VALUE                = "true";

//  Used in profiles.jsp
  static final String BUTTON_EDIT_ISSUER       = "buttoneditissuer"; 
  static final String BUTTON_DELETE_ISSUER     = "buttondeleteissuer";
  static final String BUTTON_ADD_ISSUER        = "buttonaddissuer"; 
  static final String BUTTON_RENAME_ISSUER     = "buttonrenameissuer";
  static final String BUTTON_CLONE_ISSUER      = "buttoncloneissuer";

  static final String SELECT_ISSUER            = "selectissuer";
  static final String SELECT_ROLE      		   = "selectrole";
  static final String TEXTFIELD_ALIAS          = "textfieldalias";
  static final String HIDDEN_ALIAS             = "hiddenalias";  
  
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String SELECT_AVAILABLEHARDTOKENPROFILES            = "selectavailablehardtokenprofiles";
  static final String TEXTFIELD_DESCRIPTION    = "textfielddescription";



  static final String SELECT_TYPE                         = "selecttype";
  String alias = null;
  String certsn = null;%>
<%
    // Initialize environment
  String includefile = "hardtokenissuerspage.jspf";

  boolean  issuerexists             = false;
  boolean  issuerdeletefailed       = false;

  String value=null;
  HardTokenIssuer issuer=null;     

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS); 
                                    tokenbean.initialize(request, ejbcawebbean);
                                    cabean.initialize(ejbcawebbean); 

  String THIS_FILENAME                    = globalconfiguration.getHardTokenPath() + "/edithardtokenissuers.jsp";

  Map caidtonamemap = cabean.getCAIdToNameMap();
%>
 
<head>
  <title><c:out value="<%=globalconfiguration.getEjbcaTitle()%>" /></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
  <script type="text/javascript" src="<%=globalconfiguration .getAdminWebPath()%>ejbcajslib.js"></script>
</head>

<body>

<%
    RequestHelper.setDefaultCharacterEncoding(request);

   // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ISSUERS)){
      if( request.getParameter(BUTTON_EDIT_ISSUER) != null){
          // Display  profilepage.jspf
         alias = request.getParameter(SELECT_ISSUER);
         if(alias != null){
           if(!alias.trim().equals("")){
     includefile="hardtokenissuerpage.jspf"; 
           } 
           else{ 
    alias= null;
          } 
        }
        if(alias == null){   
          includefile="hardtokenissuerspage.jspf";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_ISSUER) != null) {
          // Delete profile and display profilespage. 
          alias = request.getParameter(SELECT_ISSUER);
          if(alias != null){
    if(!alias.trim().equals("")){
      issuerdeletefailed = !tokenbean.removeHardTokenIssuer(alias);
    }
          }
          includefile="hardtokenissuerspage.jspf";          
      }
      if( request.getParameter(BUTTON_RENAME_ISSUER) != null){ 
         // Rename selected profile and display profilespage.
       String newalias  = request.getParameter(TEXTFIELD_ALIAS);       
       String oldalias = request.getParameter(SELECT_ISSUER);
       int roleId = Integer.parseInt(request.getParameter(SELECT_ROLE));
       
       if(oldalias != null && newalias != null){
         if(!newalias.trim().equals("") && !oldalias.trim().equals("")){
           try{
     tokenbean.renameHardTokenIssuer(oldalias,newalias.trim(), roleId);
           }catch( HardTokenIssuerExistsException e){
     issuerexists=true;
           }        
         }
       }      
       includefile="hardtokenissuerspage.jspf"; 
      }
      if( request.getParameter(BUTTON_ADD_ISSUER) != null){
         // Add profile and display profilespage.         
         alias = request.getParameter(TEXTFIELD_ALIAS);        
         int roleId = Integer.parseInt(request.getParameter(SELECT_ROLE));
         if(alias != null){
           if(!alias.trim().equals("")){
     try{              
       tokenbean.addHardTokenIssuer(alias.trim(), roleId);
     }catch( HardTokenIssuerExistsException e){
       issuerexists=true;
     }
           }      
         }
         includefile="hardtokenissuerspage.jspf"; 
      }
      if( request.getParameter(BUTTON_CLONE_ISSUER) != null){
         // clone profile and display profilespage.
       String newalias  = request.getParameter(TEXTFIELD_ALIAS);       
       String oldalias = request.getParameter(SELECT_ISSUER);
       int roleId = Integer.parseInt(request.getParameter(SELECT_ROLE));
       if(oldalias != null && newalias != null){
         if(!oldalias.trim().equals("") && !newalias.trim().equals("")){
     try{ 
       tokenbean.cloneHardTokenIssuer(oldalias.trim(),newalias.trim(), roleId);
     }catch( HardTokenIssuerExistsException e){
       issuerexists=true;
     }
         }
       }      
       includefile="hardtokenissuerspage.jspf"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ISSUER)){
         // Display edit access rules page.
       alias = request.getParameter(HIDDEN_ALIAS);       
       if(alias != null){
         if(!alias.trim().equals("")){
           if(request.getParameter(BUTTON_SAVE) != null){
     issuer = tokenbean.getHardTokenIssuerInformation(alias).getHardTokenIssuer();
     // Save changes.
     ArrayList availableprofiles = new ArrayList();
 
     String[] values = request.getParameterValues(SELECT_AVAILABLEHARDTOKENPROFILES);
     
     if(values!= null){
       for(int i=0; i< values.length; i++){
         availableprofiles.add(Integer.valueOf(values[i]));                     
       }
     } 
     issuer.setAvailableHardTokenProfiles(availableprofiles);
              
     String description = request.getParameter(TEXTFIELD_DESCRIPTION);
     if(description == null)
       description = "";
     issuer.setDescription(description);


     tokenbean.changeHardTokenIssuer(alias,issuer);
     includefile="hardtokenissuerspage.jspf";
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
      // Don't save changes.
     includefile="hardtokenissuerspage.jspf";
           }
         }
      }
    }
  }

  Collection authroles = ejbcawebbean.getInformationMemory().getHardTokenIssuingRoles();
  Map adminidtonamemap = ejbcawebbean.getInformationMemory().getRoleIdToNameMap();

 // Include page
  if( includefile.equals("hardtokenissuerspage.jspf")){
%>
   <%@ include file="hardtokenissuerspage.jspf" %>
<%
    }
  if( includefile.equals("hardtokenissuerpage.jspf")){
%>
   <%@ include file="hardtokenissuerpage.jspf" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
