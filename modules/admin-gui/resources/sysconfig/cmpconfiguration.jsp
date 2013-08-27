<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, 
				org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.ui.web.RequestHelper,
				org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.cesecore.certificates.certificateprofile.CertificateProfile, 
				org.ejbca.ui.web.admin.cainterface.CertificateProfileDataHandler, org.cesecore.certificates.certificateprofile.CertificateProfileExistsException, 
				org.cesecore.certificates.certificateprofile.CertificateProfileConstants, org.ejbca.ui.web.CertificateView, 
				org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, 
				org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory, 
				org.cesecore.certificates.certificate.certextensions.AvailableCertificateExtension, org.cesecore.certificates.certificateprofile.CertificatePolicy,
                org.cesecore.certificates.ca.CAInfo, org.cesecore.util.ValidityDate, org.ejbca.ui.web.ParameterException, 
                org.cesecore.certificates.util.AlgorithmConstants, org.cesecore.certificates.certificate.CertificateConstants, 
                org.ejbca.core.model.authorization.AccessRulesConstants,org.ejbca.config.CmpConfiguration"%>
                
<%@page import="org.cesecore.util.YearMonthDayTime"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations 


	static final String ACTION                              		= "action";
	static final String ACTION_EDIT_ALIAS                  		= "editcmpalias";

	static final String TEXTFIELD_ALIAS                       	 	= "textfieldalias";
	static final String TEXTFIELD_DEFAULTCA					  	= "textfielddefaultca";
	static final String TEXTFIELD_EXTRACTUSERNAMECOMPONENT	  		= "textfieldextractusernamecomponent";
	static final String TEXTFIELD_CMP_RAAUTHENTICATIONMODULE   	= "textfieldcmpraauthenticationmodule";
	static final String TEXTFIELD_CMP_CLIENTAUTHENTICATIONMODULE 	= "textfieldcmpclientauthenticationmodule";
	static final String TEXTFIELD_CMP_RAAUTHENTICATIONPARAM	  	= "textfieldcmpraauthenticationparameters";
	static final String TEXTFIELD_CMP_CLIENTAUTHENTICATIONPARAM  	= "textfieldcmpclientauthenticationparameters";
	static final String TEXTFIELD_CMP_EXTRACTUSERNAMECOMP	  		= "textfieldcmpextractusernamecomponent";
	static final String TEXTFIELD_CMP_VENDORCA				  		= "textfieldcmpvendorca";
	static final String TEXTFIELD_CMP_RANAMEGENPARAM			  	= "textfieldcmpranamegenerationparameter";
	static final String TEXTFIELD_CMP_RANAMEGENPREFIX		  		= "textfieldcmpranamegenerationprefix";
	static final String TEXTFIELD_CMP_RANAMEGENPOSTFIX		  		= "textfieldcmpranamegenerationpostfix";
	static final String TEXTFIELD_CMP_RAPASSWORDGENPARAM		  	= "textfieldcmprapasswordgenerationparameter";
	static final String TEXTFIELD_CMP_CERTREQHANDLERCLASS			= "textfieldcmpcertreqhandlerclass";
	static final String TEXTFIELD_CMP_UNIDDATASOURCE				= "textfieldcmpuniddatasource";
	
	static final String BUTTON_ADD_ALIAS						 	= "buttonaliasadd";
	static final String BUTTON_DELETE_ALIAS					 	= "buttondeletealias";
	static final String BUTTON_EDIT_ALIAS					 		= "buttoneditalias";
	static final String BUTTON_RENAME_ALIAS					 	= "buttonaliasrename";
	static final String BUTTON_CLONE_ALIAS						 	= "buttonaliasclone";
	static final String BUTTON_SAVE							 	= "buttonsave";
	static final String BUTTON_CANCEL							 	= "buttoncancel";
	
	static final String CHECKBOX_CMP_RAMODE						= "checkboxcmpramode";
	static final String CHECKBOX_CMP_CLIENTMODE					= "checkboxcmpclientmode";
	static final String CHECKBOX_CMP_VENDORMODE					= "checkcmpvendormode";
	static final String CHECKBOX_CMP_KUR_USEAUTOMATICKEYUPDATE  	= "checkboxcmpuseautomatickeyupdate";
	static final String CHECKBOX_CMP_KUR_USESAMEKEYS				= "checkboxcmpkurusesamekeys";
	static final String CHECKBOX_CMP_ALLOWRAVERIFYPOPO				= "checkboxcmpallowraverifypopo";
	static final String CHECKBOX_CMP_ALLOWCUSTOMSERNO				= "checkboxcmpallowcustomserno";
	
	
	static final String LIST_CMPDEFAULTCAS					   		= "listcmpdefaultcas";
	static final String LIST_CMPRACAS						   		= "listcmpracas";
	static final String LIST_CMPRESPONSEPROTECTION_RA		   		= "listcmpresponseprotectionra";
	static final String LIST_CMPRESPONSEPROTECTION_CLIENT	   		= "listcmpresponseprotectionclient";
	static final String LIST_CMPAUTHMODULES_RA						= "listcmpauthmodulesra";
	static final String LIST_CMPRANAMEGENERATIONSCHEME		   		= "listcmpranamegenerationscheme";
	static final String LIST_CMPEEPROFILES					   		= "listcmpeeprofile";
	static final String LIST_CMPCERTPROFILES				   		= "listcmpcertprofiles";
	
	static final String SELECT_ALIASES                       		= "selectaliases";

	static final String HIDDEN_ALIAS                         		= "hiddenalias";

	static final String VALUE_TRUE							   		= "true";
	static final String VALUE_FALSE						   		= "false";


 

  // Declare Language file.
%>
<% 

  // Initialize environment
  String alias = null;
  String includefile = "cmpaliasespage.jspf"; 

  boolean  triedtoaddexistingalias    = false;
  boolean  aliasexists             = false;
  boolean  aliasDeletionFailed = false;
  
  boolean ramode = false;

  GlobalConfiguration gc = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITCERTIFICATEPROFILES); 
                                            cabean.initialize(ejbcawebbean); 
  
  CmpConfiguration cmpconfig = ejbcawebbean.getCMPConfiguration();

  String THIS_FILENAME            = gc.getAdminWebPath() +  "/sysconfig/cmpconfiguration.jsp";
  
  boolean issuperadministrator = false;
  try{
    issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(AuthorizationDeniedException ade){}   

  String[] keyusagetexts = CertificateView.KEYUSAGETEXTS;
  int[] defaultavailablebitlengths = CertificateProfile.DEFAULTBITLENGTHS;
%>
 
<head>
  <title><c:out value="<%= gc.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= gc.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%
	// Determine action 
 	RequestHelper.setDefaultCharacterEncoding(request);
  		if( request.getParameter(ACTION) != null){
    		if( request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS)){
    			
      			if( request.getParameter(BUTTON_EDIT_ALIAS) != null){
          			// Display  profilepage.jsp
         			alias = request.getParameter(SELECT_ALIASES);
         			if(alias != null){
           				if(!alias.trim().equals("")){
        	   				if(!cmpconfig.aliasExists(alias)) {
        	   					cmpconfig.addAlias(alias);
        	   				}
               				includefile="cmpaliaspage.jspf"; 
           				}
         			}
         			if(alias == null){   
          				includefile="cmpaliasespage.jspf";     
         			}
      			}
      			
      			if( request.getParameter(BUTTON_DELETE_ALIAS) != null) {
          			// Delete profile and display profilespage. 
          			alias = request.getParameter(SELECT_ALIASES);
          			if(alias != null && (!alias.trim().equals("")) ){
              			cmpconfig.removeAlias(alias);
          			}
        			ejbcawebbean.saveCMPConfiguration();
          			includefile="cmpaliasespage.jspf";             
      			}
      			
      			if( request.getParameter(BUTTON_RENAME_ALIAS) != null){ 
         			// Rename selected profile and display profilespage.
       	 			String newalias = request.getParameter(TEXTFIELD_ALIAS);
         			String oldalias = request.getParameter(SELECT_ALIASES);
         			if(oldalias != null && newalias != null && !newalias.trim().equals("") && !oldalias.trim().equals("") ){
             			cmpconfig.renameAlias(oldalias, newalias);
         			}
        			ejbcawebbean.saveCMPConfiguration();
         			includefile="cmpaliasespage.jspf"; 
      			}
      			if( request.getParameter(BUTTON_ADD_ALIAS) != null){
         			alias = request.getParameter(TEXTFIELD_ALIAS);
         			if(alias != null && (!alias.trim().equals("")) ) {
        	  			cmpconfig.addAlias(alias);
         			}
        			ejbcawebbean.saveCMPConfiguration();
         			includefile="cmpaliasespage.jspf"; 
      			}
      			if( request.getParameter(BUTTON_CLONE_ALIAS) != null){
         			// clone profile and display profilespage.
         			String newalias = request.getParameter(TEXTFIELD_ALIAS);
         			String oldalias = request.getParameter(SELECT_ALIASES);
         			if(oldalias != null && newalias != null){
           				if(!newalias.trim().equals("") && !oldalias.trim().equals("")){
        	 				cmpconfig.cloneAlias(oldalias, newalias);
           				}
         			}
        			ejbcawebbean.saveCMPConfiguration();
         			includefile="cmpaliasespage.jspf"; 
      			}
      			
    		} // if( request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS))
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    		if(request.getParameter(BUTTON_SAVE) != null) {
       			alias = request.getParameter(HIDDEN_ALIAS);
       			if((alias != null) && (!alias.trim().equals(""))){

						//defaultca        	 
            			String value = request.getParameter(LIST_CMPDEFAULTCAS).trim();
            			if ( value!=null && value.length()>0 ){
            				String cadn = cabean.getCAInfo(value).getCAInfo().getSubjectDN();
							cmpconfig.setCMPDefaultCA(alias, cadn);
            			}
  
            			// oprational mode
            			String valueClient = request.getParameter(CHECKBOX_CMP_CLIENTMODE);
            			String valueRA = request.getParameter(CHECKBOX_CMP_RAMODE);
						if((valueClient!=null)) {
							ramode = false;
						} else if((valueRA != null)) {
							ramode = true;
						}
       					cmpconfig.setRAMode(alias, ramode);
       					
						// response protection
						if(ramode) {
							value = request.getParameter(LIST_CMPRESPONSEPROTECTION_RA).trim();
						} else {
							value = request.getParameter(LIST_CMPRESPONSEPROTECTION_CLIENT).trim();
						}
            			if ( value!=null && value.length()>0 ){
							cmpconfig.setResponseProtection(alias, value);
            			}

            			// authentication module
            			String authmodule = "";
            			String authparam = "";
            			if(!ramode) {
							authmodule = request.getParameter(TEXTFIELD_CMP_CLIENTAUTHENTICATIONMODULE).trim();
            				authparam = request.getParameter(TEXTFIELD_CMP_CLIENTAUTHENTICATIONPARAM).trim();
            			} else {
            				authmodule = request.getParameter(LIST_CMPAUTHMODULES_RA).trim();
            				authparam = request.getParameter(TEXTFIELD_CMP_RAAUTHENTICATIONPARAM).trim();
            			}
            			if(value != null){
	            			cmpconfig.setAuthenticationModule(alias, authmodule);
            				cmpconfig.setAuthenticationParameters(alias, authparam);
            			}
            
            			// extract username component -- client mode
            			value = request.getParameter(TEXTFIELD_CMP_EXTRACTUSERNAMECOMP);
            			if(value != null){
            				cmpconfig.setExtractUsernameComponent(alias, value);
            			}

            			// vendor mode -- client mode
            			value = request.getParameter(CHECKBOX_CMP_VENDORMODE);
            			boolean vendormode = false;
            			if((value != null) && !ramode){
            				vendormode = true;
            			}
            			cmpconfig.setVendorMode(alias, vendormode);

            			// vendor CA -- client mode
            			value = request.getParameter(TEXTFIELD_CMP_VENDORCA);
            			if(value != null){
	            			cmpconfig.setVendorCA(alias, value);
            			}
             
            			// allow verify popo -- ra mode
            			value = request.getParameter(CHECKBOX_CMP_ALLOWRAVERIFYPOPO);
            			cmpconfig.setAllowRAVerifyPOPO(alias, (value != null));
             
            			// ra name generation scheme
            			value = request.getParameter(LIST_CMPRANAMEGENERATIONSCHEME);
            			if(value != null){
            				cmpconfig.setRANameGenScheme(alias, value);
            			}

            			// ra name generation parameters
            			value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPARAM);
            			if(value != null){
            				cmpconfig.setRANameGenParams(alias, value);
            			}

            			// ra name generation prefix
            			value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPREFIX);
            			if(value != null){
            				cmpconfig.setRANameGenPrefix(alias, value);
            			}

            			// ra name generation postfix
            			value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPOSTFIX);
            			if(value != null){
            				cmpconfig.setRANameGenPostfix(alias, value);
            			}

            			// ra password generation parameters
            			value = request.getParameter(TEXTFIELD_CMP_RAPASSWORDGENPARAM);
            			if(value != null){
            				cmpconfig.setRAPwdGenParams(alias, value);
            			}
             
            			// allow custom serno
            			value = request.getParameter(CHECKBOX_CMP_ALLOWCUSTOMSERNO);
            			cmpconfig.setAllowRACustomSerno(alias, (value != null));
             
            			// ra endentity profile
            			value = request.getParameter(LIST_CMPEEPROFILES);
            			if(value != null){
            				cmpconfig.setRAEEProfile(alias, value);
            			}
             
            			// ra certprofile
            			value = request.getParameter(LIST_CMPCERTPROFILES);
            			if(value != null) {
            				cmpconfig.setRACertProfile(alias, value);
            			}
             
         				// ra CA  
		 				value = request.getParameter(LIST_CMPRACAS);
	     				if ( (value != null) && (value.trim().length() > 0) ) {
	    					cmpconfig.setRACAName(alias, value);
	     				}

	     
	     	
	     	
	     	
	        			// KUR automatic keyupdate
            			value = request.getParameter(CHECKBOX_CMP_KUR_USEAUTOMATICKEYUPDATE);
            			cmpconfig.setKurAllowAutomaticUpdate(alias, (value != null));
              
            			// KUR update with same key
            			value = request.getParameter(CHECKBOX_CMP_KUR_USESAMEKEYS);
            			cmpconfig.setKurAllowSameKey(alias, (value != null));
              
            			
            			
            			
            			// CertReqHandlerClass
            			value = request.getParameter(TEXTFIELD_CMP_CERTREQHANDLERCLASS);
            			if(value != null) {
            				cmpconfig.setCertReqHandlerClass(alias, value);
            			}
            			
            			// Unid Datasource
            			value = request.getParameter(TEXTFIELD_CMP_UNIDDATASOURCE);
            			if(value != null) {
							cmpconfig.setUnidDataSource(alias, value);
            			}
            			
            			
            			
            			
            			
            			
            			ejbcawebbean.saveCMPConfiguration();


           
           				if(request.getParameter(BUTTON_CANCEL) != null){
              				// Don't save changes.
							//              cabean.setTempCertificateProfile(null);
              				includefile="cmpaliasespage.jspf";
           				}
           				if(includefile == null ) {
                 			includefile="cmpaliasespage.jspf";
           				}
       			} // if((alias != null) && (!alias.trim().equals("")))
    		} // if(request.getParameter(BUTTON_SAVE) != null)
    
  		} // if( request.getParameter(ACTION) != null)

 // Include page
  if( includefile.equals("cmpaliaspage.jspf")){
%>
   <%@ include file="cmpaliaspage.jspf" %>
<%}
  if( includefile.equals("cmpaliasespage.jspf")){ %>
   <%@ include file="cmpaliasespage.jspf" %> 
<%}

   // Include Footer 
   String footurl =   gc.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
