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
	static final String TEXTFIELD_EST_REQUIREUSERNAME						= "textfieldrequireusername";
	static final String TEXTFIELD_EST_REQUIREPASSWORD						= "textfieldrequirepassword";
	
	static final String BUTTON_ADD_ALIAS						= "buttonaliasadd";
	static final String BUTTON_DELETE_ALIAS					 	= "buttondeletealias";
	static final String BUTTON_EDIT_ALIAS					 	= "buttoneditalias";
	static final String BUTTON_VIEW_ALIAS						= "buttonviewalias";
	static final String BUTTON_RENAME_ALIAS					 	= "buttonaliasrename";
	static final String BUTTON_CLONE_ALIAS						= "buttonaliasclone";
	static final String BUTTON_SAVE							 	= "buttonsave";
	static final String BUTTON_CANCEL							= "buttoncancel";
	static final String BUTTON_RELOAD							= "buttonreload";
	
	static final String CHECKBOX_EST_VENDORMODE					= "checkestvendormode";
	static final String CHECKBOX_EST_REQUIRECERT  				= "checkboxrequirecert";
	static final String CHECKBOX_EST_KUR_USESAMEKEYS 			= "checkboxkurusesamekeys";

	static final String LIST_ESTDEFAULTCA					   		= "listestdefaultca";
	static final String LIST_ESTEEPROFILES					   		= "listesteeprofile";
	static final String LIST_ESTCERTPROFILES				   		= "listestcertprofiles";
		
	static final String SELECT_ALIASES                       		= "selectaliases";
	static final String HIDDEN_ALIAS                         		= "hiddenalias";
	static final String CHECKBOX_VALUE								= "true"; 
	 
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
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <script type="text/javascript" src="<%= gc.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>
<jsp:include page="../adminmenu.jsp" />
<div class="main-wrapper">
<div class="container">

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
    		       				estConfigClone.setDefaultCAID(alias, 0);
    		       			} else {
    		                	estConfigClone.setDefaultCAID(alias, Integer.valueOf(value));
    		       			}
									   
							// ra endentity profile
							value = request.getParameter(LIST_ESTEEPROFILES);
							if(value != null){
								estConfigClone.setEndEntityProfileID(alias, Integer.valueOf(value));
							}
							   
							// ra certprofile
							value = request.getParameter(LIST_ESTCERTPROFILES);
							if(value != null) {
								estConfigClone.setCertProfileID(alias, Integer.valueOf(value));
							}

							// require cert
							value = request.getParameter(CHECKBOX_EST_REQUIRECERT);
							estConfigClone.setCert(alias, value != null);

							// require username
							value = request.getParameter(TEXTFIELD_EST_REQUIREUSERNAME);
							estConfigClone.setUsername(alias, value == null ? "" : value);

							// require password
							value = request.getParameter(TEXTFIELD_EST_REQUIREPASSWORD);
							estConfigClone.setPassword(alias, value == null ? "" : value);

							// allow reenroll with same key
							value = request.getParameter(CHECKBOX_EST_KUR_USESAMEKEYS);
							estConfigClone.setKurAllowSameKey(alias, value != null);

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
<%} %>

</div> <!-- Container -->

<%
   // Include Footer 
   String footurl =   gc.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</div> <!-- main-wrapper -->
</body>
</html>
