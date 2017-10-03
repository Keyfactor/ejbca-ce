<%@page import="org.apache.commons.lang.StringUtils"%>
<%@page import="org.apache.commons.lang.ArrayUtils"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, 
				org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.ui.web.RequestHelper,
				org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.cesecore.certificates.certificateprofile.CertificateProfile, 
				org.cesecore.certificates.certificateprofile.CertificateProfileExistsException, 
				org.cesecore.certificates.certificateprofile.CertificateProfileConstants, org.ejbca.ui.web.CertificateView, 
				org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, 
				org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory, 
				org.cesecore.certificates.certificateprofile.CertificatePolicy,
                org.cesecore.certificates.ca.CAInfo, org.ejbca.ui.web.ParameterException, 
                org.cesecore.certificates.util.AlgorithmConstants, org.cesecore.certificates.certificate.CertificateConstants, 
                org.ejbca.core.model.authorization.AccessRulesConstants,org.ejbca.config.EstConfiguration, org.ejbca.core.model.ra.UsernameGeneratorParams,
                org.cesecore.authorization.control.StandardRules"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations 


	static final String ACTION                              		= "action";
	static final String ACTION_EDIT_ALIAS                  		= "actioneditestalias";
	static final String ACTION_VIEW_ALIAS                  		= "actionviewestalias";
	static final String ACTION_EDIT_ALIASES						= "actioneditestaliases";

	static final String TEXTFIELD_ALIAS                       	 	= "textfieldalias";
	static final String TEXTFIELD_EST_RANAMEGENPARAM			  	= "textfieldestranamegenerationparameter";
	static final String TEXTFIELD_EST_RANAMEGENPREFIX		  		= "textfieldestranamegenerationprefix";
	static final String TEXTFIELD_EST_RANAMEGENPOSTFIX		  		= "textfieldestranamegenerationpostfix";
	static final String TEXTFIELD_EST_RAPASSWORDGENPARAM		  	= "textfieldestrapasswordgenerationparameter";
	static final String TEXTFIELD_HMACPASSWORD						= "textfieldhmacpassword";
	static final String TEXTFIELD_NESTEDMESSAGETRUSTEDCERTPATH		= "textfieldnestedmessagetrustedcertificatespath";
	
	static final String BUTTON_ADD_ALIAS						= "buttonaliasadd";
	static final String BUTTON_DELETE_ALIAS					 	= "buttondeletealias";
	static final String BUTTON_EDIT_ALIAS					 	= "buttoneditalias";
	static final String BUTTON_VIEW_ALIAS						= "buttonviewalias";
	static final String BUTTON_RENAME_ALIAS					 	= "buttonaliasrename";
	static final String BUTTON_CLONE_ALIAS						= "buttonaliasclone";
	static final String BUTTON_SAVE							 	= "buttonsave";
	static final String BUTTON_CANCEL							= "buttoncancel";
	static final String BUTTON_RELOAD							= "buttonreload";
	static final String BUTTON_ADDVENDORCA						= "buttonaddvendorca";
	static final String BUTTON_REMOVEVENDORCA					= "buttonremovevendorca";
	static final String BUTTON_ADD_NAMEGENPARAM_DN				= "buttonaddnamegenparamdn";
	static final String BUTTON_REMOVE_NAMEGENPARAM_DN			= "buttonremovenamegenparamdn";
	
	static final String RADIO_ESTMODE								= "radioestmode";
	static final String RADIO_NAMEGENSCHEME						= "radionnamegenscheme";
	static final String RADIO_HMACPASSWORD							= "radiohmacpassword";

	
	static final String CHECKBOX_EST_VENDORMODE					= "checkestvendormode";
	static final String CHECKBOX_EST_KUR_USEAUTOMATICKEYUPDATE  	= "checkboxestuseautomatickeyupdate";
	static final String CHECKBOX_EST_KUR_USESAMEKEYS				= "checkboxestkurusesamekeys";
	static final String CHECKBOX_EST_ALLOWRAVERIFYPOPO				= "checkboxestallowraverifypopo";
	static final String CHECKBOX_EST_ALLOWCUSTOMSERNO				= "checkboxestallowcustomserno";
	static final String CHECKBOX_HMAC								= "checkboxhmac";
	static final String CHECKBOX_EEC								= "checkboxeec";
	static final String CHECKBOX_REGTOKEN							= "checkboxregtoken";
	static final String CHECKBOX_DNPART							= "checkboxdnpart";
	static final String CHECKBOX_OMITVERIFICATIONINECC				= "checkboxomitverificationsinecc";

	
	static final String LIST_ESTDEFAULTCA					   		= "listestdefaultca";
	static final String LIST_ESTRACAS						   		= "listestracas";
	static final String LIST_ESTRESPONSEPROTECTION		   		    = "listestresponseprotection";
	static final String LIST_ESTEEPROFILES					   		= "listesteeprofile";
	static final String LIST_ESTCERTPROFILES				   		= "listestcertprofiles";
	static final String LIST_ECCCAS								= "listecccas";
	static final String LIST_DNPARTS								= "listdnparts";
	static final String LIST_EXTRACTUSERNAMECOMP					= "listextractusernamecomp";
	static final String LIST_VENDORCA								= "listvendorca";
	static final String LIST_NAMEGENPARAM_DN						= "listnamegenparamdn";
		
	static final String SELECT_ALIASES                       		= "selectaliases";
	static final String HIDDEN_ALIAS                         		= "hiddenalias";
	static final String CHECKBOX_VALUE								= "true"; 
	 
	 
	List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "serialNumber", "givenName", "initials", "surname", "title", 
			   		"unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress", 
			   		"telephoneNumber", "pseudonym", "streetAddress", "name", "CIF", "NIF");


 

  // Declare Language file.
%>
<%
    // Initialize environment
  String alias = null;
  String includefile = "estaliasespage.jspf"; 

  boolean  triedtoaddexistingalias    = false;
  boolean  aliasDeletionFailed = false;
  boolean  triedrenametoexistingalias = false;
  boolean  triedclonetoexistingalias = false;
  
  boolean ramode = false;
  boolean pbe = false;

  GlobalConfiguration gc = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource()); 
                                    cabean.initialize(ejbcawebbean); 
  boolean authorizedToEdit =  ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());

  
  ejbcawebbean.clearEstCache();
  EstConfiguration estconfig = ejbcawebbean.getEstConfiguration();
  EstConfiguration estConfigClone = null;

  String THIS_FILENAME            = gc.getAdminWebPath() +  "/sysconfig/estconfiguration.jsp";
%>
 
<head>
  <title><c:out value="<%= gc.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= gc.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%
	// Determine action 
 	RequestHelper.setDefaultCharacterEncoding(request);

  	if( request.getParameter(ACTION) != null){
    		if( request.getParameter(ACTION).equals(ACTION_EDIT_ALIASES)){			
    			ejbcawebbean.clearEstConfigClone();    			
    				if( request.getParameter(BUTTON_VIEW_ALIAS) != null){
      					// Display  estaliaspage.jsp
     					alias = request.getParameter(SELECT_ALIASES);
     					if(alias != null && !alias.trim().equals("")) {
    	   					if(!estconfig.aliasExists(alias)) {
    	   						estconfig.addAlias(alias);
    	   					}
    	   					estConfigClone = ejbcawebbean.getEstConfigForEdit(alias);
           					includefile="estaliaspage.jspf"; 
     					} else {
      						includefile="estaliasespage.jspf";     
     					}
    				    authorizedToEdit = false;
  					}
    				
      				if( request.getParameter(BUTTON_EDIT_ALIAS) != null){
      				  authorizedToEdit = ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
          					// Display  estaliaspage.jsp
         					alias = request.getParameter(SELECT_ALIASES);
         					if(alias != null){
           							if(!alias.trim().equals("")){
        	   								if(!estconfig.aliasExists(alias)) {
        	   										estconfig.addAlias(alias);
        	   								}
        	   							   	estConfigClone = ejbcawebbean.getEstConfigForEdit(alias);
               								includefile="estaliaspage.jspf"; 
           							}
         					}
         					if(alias == null){   
          							includefile="estaliasespage.jspf";     
         					}
      				}
      			
      				if( request.getParameter(BUTTON_DELETE_ALIAS) != null) {
          					// Delete profile and display profilespage. 
          					alias = request.getParameter(SELECT_ALIASES);
          					if(alias != null && (!alias.trim().equals("")) ){
                					ejbcawebbean.removeEstAlias(alias);
                					estconfig = ejbcawebbean.getEstConfiguration();
                					if(estconfig.aliasExists(alias)) {
                						aliasDeletionFailed = true;
                					}
          					}
          					includefile="estaliasespage.jspf";             
      				}

      				if( request.getParameter(BUTTON_RENAME_ALIAS) != null){ 
      						// Rename selected profile and display profilespage.
      					    String newalias = request.getParameter(TEXTFIELD_ALIAS);
      					    String oldalias = request.getParameter(SELECT_ALIASES);
      					    if(oldalias != null && newalias != null && !newalias.trim().equals("") && !oldalias.trim().equals("") ){
      					    		if(estconfig.aliasExists(newalias)) {
      					    			triedrenametoexistingalias = true;
      					    		} else {
      					    			ejbcawebbean.renameEstAlias(oldalias, newalias);
      					    			estconfig = ejbcawebbean.getEstConfiguration();
      					    		}
      					    }
      					    includefile="estaliasespage.jspf"; 
      				}
      				
      				if( request.getParameter(BUTTON_ADD_ALIAS) != null){
      						alias = request.getParameter(TEXTFIELD_ALIAS);
      					    if(alias != null && (!alias.trim().equals("")) ) {
      					    		if(estconfig.aliasExists(alias)) {
      					    			triedtoaddexistingalias = true;
      					    		} else {
      					    			ejbcawebbean.addEstAlias(alias);
      					    			estconfig = ejbcawebbean.getEstConfiguration();
      					    		}
      					    }
      					    includefile="estaliasespage.jspf"; 
      				}
      				
      				if( request.getParameter(BUTTON_CLONE_ALIAS) != null){
      						// clone profile and display profilespage.
      					    String newalias = request.getParameter(TEXTFIELD_ALIAS);
      					    String oldalias = request.getParameter(SELECT_ALIASES);
      					    if(oldalias != null && newalias != null && !newalias.trim().equals("") && !oldalias.trim().equals("")){
      					    	if(estconfig.aliasExists(newalias)) {
      					    		triedclonetoexistingalias = true;
      					    	} else {
					      		   ejbcawebbean.cloneEstAlias(oldalias, newalias);
					      		 	estconfig = ejbcawebbean.getEstConfiguration();
      					    	}
      					    }
      					    includefile="estaliasespage.jspf"; 
      				}

    		}      				
      				
    		
    		if(request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS)) {
    				alias = request.getParameter(HIDDEN_ALIAS);
    		       	if(alias != null) {
    		       		if(!alias.trim().equals("")) {
    		       	    	
    		       		   	estConfigClone = ejbcawebbean.getEstConfigForEdit(alias);
    		       			
    		       			//Save changes
    		       						
    		       			//defaultCA
    		       			String value = request.getParameter(LIST_ESTDEFAULTCA);
    		       			if((value==null) || (value.length() == 0)) {
    		       				estConfigClone.setDefaultCA(alias, "");
    		       			} else {
    		                	estConfigClone.setDefaultCA(alias, value);
    		       			}
									   
							   // ra endentity profile
							   value = request.getParameter(LIST_ESTEEPROFILES);
							   if(value != null){
								estConfigClone.setEndEntityProfile(alias, value);
							   }
							   
							   // ra certprofile
							   value = request.getParameter(LIST_ESTCERTPROFILES);
							   if(value != null) {
								estConfigClone.setCertProfile(alias, value);
							   }

    				        includefile="estaliaspage.jspf";
    			        
    				        if(request.getParameter(BUTTON_SAVE) != null) {
    				        		ejbcawebbean.updateEstConfigFromClone(alias);
    			        	   		includefile="estaliasespage.jspf";
    			        	}
    				        
    		       		} // if(!alias.trim().equals(""))
    		       			
               			if(request.getParameter(BUTTON_CANCEL) != null){
              				// Don't save changes.
             				includefile="estaliasespage.jspf";
           				}
    		       		
    		       	} // if((alias != null) )
    	    } // if(request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS))

  		} // if( request.getParameter(ACTION) != null)

 // Include page
  if( includefile.equals("estaliaspage.jspf")){
%>
   <%@ include file="estaliaspage.jspf" %>
<%}
  if( includefile.equals("estaliasespage.jspf")){ %>
   <%@ include file="estaliasespage.jspf" %> 
<%}

   // Include Footer 
   String footurl =   gc.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
